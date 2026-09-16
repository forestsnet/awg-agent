"""HTTP-агент для AmneziaWG.

Замена веб-панели amnezia-wg-easy: ручки те же, поэтому бот работает с
агентом без правок, а существующие установки переезжают подменой
контейнера. Отличий три, и все три — причина, по которой агент написан:

  * протокол 3.1 (HeaderProtectionKey, RandomTrailers, DisableCookies) —
    панель писала параметры только до 2.0, хотя тулзы умеют больше;
  * свои сигнатурные пакеты I1..I5 у каждого клиента, а не случайные
    числа, которые тулзы всё равно не понимают;
  * наш код и наша лицензия: панель распространялась под
    NonCommercial-лицензией, а мы продаём готовые боты.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, auth, awg, config, render
from .state import store

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("agent")

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

app = FastAPI(title="forestsnet awg-agent", version=__version__, docs_url=None, redoc_url=None)


# ── Модели запросов ─────────────────────────────────────────────────

class SessionIn(BaseModel):
    password: str = ""
    remember: bool = False


class ClientIn(BaseModel):
    name: str = Field(default="", max_length=120)


class NameIn(BaseModel):
    name: str = Field(default="", max_length=120)


# ── Старт ───────────────────────────────────────────────────────────

@app.on_event("startup")
async def _startup() -> None:
    if not config.PASSWORD_HASH:
        raise RuntimeError(
            "PASSWORD_HASH не задан — агент не поднимается без пароля"
        )
    await store.load()
    if not store.server.get("session_secret"):
        store.server["session_secret"] = auth.new_secret()
        await store.persist()
    if config.WG_AUTO_UP:
        try:
            await awg.up()
            logger.info("интерфейс %s поднят", config.WG_INTERFACE)
        except awg.AwgError as exc:
            # Не падаем: API должен отвечать даже когда интерфейс не
            # встал — иначе про причину узнать неоткуда.
            logger.error("интерфейс не поднялся: %s", exc)


# ── Авторизация ─────────────────────────────────────────────────────

def _authed(request: Request) -> None:
    token = request.cookies.get(auth.COOKIE_NAME)
    if not auth.valid(store.server.get("session_secret", ""), token):
        raise HTTPException(status_code=401, detail="Not Logged In")


@app.post("/api/session")
async def session_create(payload: SessionIn, response: Response) -> dict[str, Any]:
    if not auth.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Incorrect Password")
    token = auth.issue(store.server["session_secret"])
    response.set_cookie(
        auth.COOKIE_NAME, token,
        max_age=config.SESSION_MAX_AGE if payload.remember else None,
        httponly=True, samesite="lax", path="/",
    )
    return {"success": True}


@app.get("/api/session")
async def session_get(request: Request) -> dict[str, Any]:
    token = request.cookies.get(auth.COOKIE_NAME)
    return {"authenticated": auth.valid(store.server.get("session_secret", ""), token)}


@app.delete("/api/session")
async def session_delete(response: Response) -> dict[str, Any]:
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"success": True}


# ── Клиенты ─────────────────────────────────────────────────────────

def _iso(ts: Optional[int]) -> Optional[str]:
    if not ts:
        return None
    import time as _time
    return _time.strftime("%Y-%m-%dT%H:%M:%S.000Z", _time.gmtime(ts))


def _out(client: dict[str, Any], stats: dict[str, Any]) -> dict[str, Any]:
    live = stats.get(client["public_key"]) or {}
    return {
        "id": client["id"],
        "name": client["name"],
        "enabled": bool(client.get("enabled", True)),
        "address": client["address"],
        "publicKey": client["public_key"],
        "createdAt": client.get("created_at"),
        "updatedAt": client.get("updated_at"),
        "downloadableConfig": True,
        "persistentKeepalive": str(config.WG_PERSISTENT_KEEPALIVE),
        "latestHandshakeAt": _iso(live.get("latest_handshake_at")),
        "transferRx": live.get("transfer_rx", 0),
        "transferTx": live.get("transfer_tx", 0),
        "endpoint": live.get("endpoint"),
    }


@app.get("/api/wireguard/client", dependencies=[Depends(_authed)])
async def clients_list() -> list[dict[str, Any]]:
    stats = await awg.peer_stats()
    return [_out(c, stats) for c in store.clients]


@app.post("/api/wireguard/client", dependencies=[Depends(_authed)])
async def client_create(payload: ClientIn) -> dict[str, Any]:
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Имя не задано")
    if any(c["name"] == name for c in store.clients):
        raise HTTPException(status_code=400, detail="Клиент с таким именем уже есть")
    client = await store.create(name)
    logger.info("клиент создан: %s (%s)", name, client["address"])
    return _out(client, await awg.peer_stats(force=True))


@app.delete("/api/wireguard/client/{key}", dependencies=[Depends(_authed)])
async def client_delete(key: str) -> dict[str, Any]:
    if not await store.delete(key):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    logger.info("клиент удалён: %s", key)
    return {"success": True}


@app.post("/api/wireguard/client/{key}/enable", dependencies=[Depends(_authed)])
async def client_enable(key: str) -> dict[str, Any]:
    if not await store.set_enabled(key, True):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return {"success": True}


@app.post("/api/wireguard/client/{key}/disable", dependencies=[Depends(_authed)])
async def client_disable(key: str) -> dict[str, Any]:
    if not await store.set_enabled(key, False):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return {"success": True}


@app.put("/api/wireguard/client/{key}/name", dependencies=[Depends(_authed)])
async def client_rename(key: str, payload: NameIn) -> dict[str, Any]:
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Имя не задано")
    if not await store.rename(key, name):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return {"success": True}


@app.get("/api/wireguard/client/{key}/configuration", dependencies=[Depends(_authed)])
async def client_config(key: str) -> PlainTextResponse:
    client = store.find(key)
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    text = render.client_conf(store.server, client)
    filename = "".join(ch for ch in client["name"] if ch.isalnum() or ch in "-_") or "client"
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="{filename}.conf"'},
    )


@app.get("/api/wireguard/client/{key}/qrcode.svg", dependencies=[Depends(_authed)])
async def client_qr(key: str) -> Response:
    client = store.find(key)
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    import io

    import segno

    # BytesIO, а не StringIO: svg-писатель segno отдаёт байты, и на
    # текстовом буфере падал с TypeError уже в проде-превью.
    buf = io.BytesIO()
    segno.make(render.client_conf(store.server, client), error="m").save(
        buf, kind="svg", scale=5, border=2, dark="#0f172a", light="#ffffff"
    )
    return Response(buf.getvalue(), media_type="image/svg+xml")


# ── Служебное ───────────────────────────────────────────────────────

@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Публичная ручка: по ней установщик и мониторинг понимают, жив ли агент."""
    params = store.server.get("params") or {}
    return {
        "ok": True,
        "agent": __version__,
        "interface": config.WG_INTERFACE,
        "up": await awg.is_up(),
        "protocol": params.get("proto"),
        "header_protection": bool(params.get("header_protection_key")),
        "random_trailers": bool(params.get("random_trailers")),
        "disable_cookies": bool(params.get("disable_cookies")),
        "clients": len(store.clients),
    }


@app.get("/api/release")
async def release() -> dict[str, Any]:
    """Совместимость: старый фронт панели спрашивал версию этой ручкой."""
    return {"version": __version__, "agent": "forestsnet/awg-agent"}


@app.exception_handler(HTTPException)
async def _http_error(_: Request, exc: HTTPException) -> JSONResponse:
    # Формат ответа тот же, что был у панели: {"error": "..."} — бот
    # разбирает именно его.
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


if os.path.isdir(WEB_DIR):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
