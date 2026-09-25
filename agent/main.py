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

from . import (REPO_URL, __build__, __version__, auth, awg, config,
               journal, net, quota, render, shaper, torrent, upstream, zones)
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
    # Опционально: контакты для отчётов торрент-блокировщика.
    telegram_id: Optional[str] = Field(default=None, max_length=64)
    email: Optional[str] = Field(default=None, max_length=254)


class ContactIn(BaseModel):
    telegram_id: Optional[str] = Field(default=None, max_length=64)
    email: Optional[str] = Field(default=None, max_length=254)


class TorrentExemptIn(BaseModel):
    exempt: bool = False


class TorrentConfigIn(BaseModel):
    enabled: Optional[bool] = None
    webhook_url: Optional[str] = Field(default=None, max_length=2048)
    webhook_secret: Optional[str] = Field(default=None, max_length=512)
    node_name: Optional[str] = Field(default=None, max_length=120)
    block_duration: Optional[int] = Field(default=None, ge=0)


class QuotaIn(BaseModel):
    # 0 — снять лимит. Период «none» — считать, но не сбрасывать.
    bytes: int = Field(default=0, ge=0)
    period: str = "none"


class ExpiresIn(BaseModel):
    # ISO-строка или null, чтобы снять срок.
    at: Optional[str] = None


class RateIn(BaseModel):
    # Бит в секунду. 0 — скорость не ограничивать.
    bps: int = Field(default=0, ge=0)


class ZoneIn(BaseModel):
    """Зона доступа: имя, подсети и через что в них ходить."""

    name: str = Field(default="", max_length=120)
    cidrs: list[str] = Field(default_factory=list)
    upstream: Optional[str] = None
    # Выпускать ли такого клиента ещё и в интернет. По умолчанию нет:
    # техник заходит за конкретными адресами, а не сёрфить.
    internet: bool = False
    # Через какой туннель уходит этот обычный трафик. Пусто — через сам
    # бастион. Нужно, когда техник лезет на клиентские машины и светить
    # туда свой адрес не надо.
    exit: Optional[str] = None


class ZonePatch(BaseModel):
    name: Optional[str] = None
    cidrs: Optional[list[str]] = None
    upstream: Optional[str] = None
    internet: Optional[bool] = None
    exit: Optional[str] = None


class ClientZoneIn(BaseModel):
    zoneId: Optional[str] = None


class UpstreamIn(BaseModel):
    """Конфиг провайдера как есть — его агент поднимет сам."""

    name: str = Field(default="", max_length=12)
    conf: str = Field(default="", max_length=20000)
    title: Optional[str] = None
    cidrs: Optional[list[str]] = None


class UpstreamPatch(BaseModel):
    title: Optional[str] = None
    cidrs: Optional[list[str]] = None
    enabled: Optional[bool] = None


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
            # Имя интерфейса в логе не для красоты: NAT на чужом
            # интерфейсе — единственная поломка, которая выглядит как
            # успешное подключение без трафика.
            logger.info(
                "интерфейс %s поднят, NAT через %s",
                config.WG_INTERFACE,
                net.egress_device(),
            )
        except awg.AwgError as exc:
            # Не падаем: API должен отвечать даже когда интерфейс не
            # встал — иначе про причину узнать неоткуда.
            logger.error("интерфейс не поднялся: %s", exc)
    # Скорость, зоны и туннели провайдеров живут в ядре и исчезают
    # вместе с контейнером. Перестраивались они только при изменении
    # клиента, поэтому после перезапуска (обновление, ребут VPS) лимиты
    # тихо переставали действовать, зоны открывались, а апстримы висели
    # опущенными — до первой правки в панели.
    await store.reapply()
    asyncio.create_task(_quota_loop())
    asyncio.create_task(torrent.watch(store))


async def _quota_loop() -> None:
    """Учёт трафика, сброс периодов, выключение по лимиту и сроку.

    Отдельной задачей, а не по запросу: клиент качает и когда панель
    закрыта, а лимит должен срабатывать и тогда.
    """
    while True:
        await asyncio.sleep(config.QUOTA_TICK_SECONDS)
        try:
            await store.tick()
        except Exception:  # noqa: BLE001
            # Сбой одного тика не должен уносить учёт целиком.
            logger.exception("тик учёта не отработал")


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
        # Лимиты. Бот эти поля игнорирует (модель отбрасывает лишнее),
        # а панели они нужны.
        "quotaBytes": int(client.get("quota_bytes") or 0),
        "quotaPeriod": client.get("quota_period") or "none",
        "quotaUsed": int(client.get("quota_used") or 0),
        "quotaResetAt": _quota_reset_at(client),
        "trafficTotal": int(client.get("traffic_total") or 0),
        "expiresAt": client.get("expires_at"),
        "disabledReason": client.get("disabled_reason"),
        "rateBps": int(client.get("rate_bps") or 0),
        "zoneId": client.get("zone_id"),
        "telegramId": client.get("telegram_id"),
        "email": client.get("email"),
        "torrentExempt": bool(client.get("torrent_exempt", False)),
    }


def _quota_reset_at(client: dict[str, Any]) -> Optional[str]:
    period = str(client.get("quota_period") or "none")
    started = quota.parse_iso(client.get("quota_started_at"))
    if period == "none" or not started:
        return None
    end = quota.period_end(started, period)
    return quota.iso(end) if end else None


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
    client = await store.create(name, telegram_id=payload.telegram_id, email=payload.email)
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


@app.put("/api/wireguard/client/{key}/quota", dependencies=[Depends(_authed)])
async def client_quota(key: str, payload: QuotaIn) -> dict[str, Any]:
    if payload.period not in quota.PERIODS:
        raise HTTPException(
            status_code=400,
            detail=f"Период должен быть одним из: {', '.join(quota.PERIODS)}",
        )
    if not await store.set_quota(key, limit=payload.bytes, period=payload.period):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    logger.info("лимит для %s: %s байт, период %s", key, payload.bytes, payload.period)
    return {"success": True}


@app.post("/api/wireguard/client/{key}/quota/reset", dependencies=[Depends(_authed)])
async def client_quota_reset(key: str) -> dict[str, Any]:
    if not await store.reset_quota(key):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return {"success": True}


@app.put("/api/wireguard/client/{key}/expires", dependencies=[Depends(_authed)])
async def client_expires(key: str, payload: ExpiresIn) -> dict[str, Any]:
    if payload.at and not quota.parse_iso(payload.at):
        raise HTTPException(status_code=400, detail="Дата должна быть в формате ISO")
    if not await store.set_expires(key, payload.at):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return {"success": True}


@app.put("/api/wireguard/client/{key}/rate", dependencies=[Depends(_authed)])
async def client_rate(key: str, payload: RateIn) -> dict[str, Any]:
    if not await store.set_rate(key, payload.bps):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    logger.info("скорость для %s: %s бит/с", key, payload.bps or "без ограничения")
    return {"success": True}


@app.get("/api/wireguard/client/{key}/usage", dependencies=[Depends(_authed)])
async def client_usage(key: str, days: int = 30) -> dict[str, Any]:
    client = store.find(key)
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    # Отдаём вместе с лимитом: иначе вызывающему нужен второй запрос за
    # списком клиентов, чтобы показать «2 из 10 ГБ».
    return {
        "days": _usage_series(client.get("history") or {}, days),
        "total": int(client.get("traffic_total") or 0),
        "quotaUsed": int(client.get("quota_used") or 0),
        "quotaBytes": int(client.get("quota_bytes") or 0),
        "quotaPeriod": client.get("quota_period") or "none",
        "quotaResetAt": _quota_reset_at(client),
        "expiresAt": client.get("expires_at"),
        "rateBps": int(client.get("rate_bps") or 0),
        "zoneId": client.get("zone_id"),
        "enabled": bool(client.get("enabled", True)),
        "disabledReason": client.get("disabled_reason"),
    }


@app.get("/api/usage", dependencies=[Depends(_authed)])
async def server_usage(days: int = 30) -> dict[str, Any]:
    """Расход по всему серверу — сумма по клиентам за те же дни."""
    merged: dict[str, dict[str, int]] = {}
    for client in store.clients:
        for date, value in (client.get("history") or {}).items():
            day = merged.setdefault(date, {"rx": 0, "tx": 0})
            day["rx"] += int(value.get("rx", 0))
            day["tx"] += int(value.get("tx", 0))
    return {
        "days": _usage_series(merged, days),
        "total": sum(int(c.get("traffic_total") or 0) for c in store.clients),
    }


def _usage_series(history: dict[str, Any], days: int) -> list[dict[str, Any]]:
    """Ряд без дырок: дни простоя тоже нужны, иначе график врёт.

    Без них график сжимает недельный простой в один пиксель, и выходит,
    что клиент качал непрерывно.
    """
    import datetime as _dt

    days = max(1, min(int(days or 30), 365))
    today = _dt.datetime.utcnow().date()
    out = []
    for offset in range(days - 1, -1, -1):
        date = (today - _dt.timedelta(days=offset)).strftime("%Y-%m-%d")
        value = history.get(date) or {}
        out.append({
            "date": date,
            "rx": int(value.get("rx", 0)),
            "tx": int(value.get("tx", 0)),
        })
    return out


def _attachment(name: str, suffix: str) -> dict[str, str]:
    """Заголовок скачивания для имени на любом языке.

    Имя клиента пишет человек, и «Сергей — дежурный» валило выдачу
    конфига пятисоткой: в заголовки HTTP помещается только latin-1.
    Поэтому ASCII-имя для старых клиентов и filename* по RFC 5987 —
    для всех остальных.
    """
    from urllib.parse import quote

    # isalnum() пропускает и кириллицу — именно на этом заголовок и
    # падал. Для простого имени оставляем строго ASCII.
    ascii_name = "".join(
        ch for ch in name if (ch.isalnum() and ch.isascii()) or ch in "-_"
    ) or "client"
    quoted = quote(f"{name}{suffix}", safe="")
    return {
        "Content-Disposition": (
            f'attachment; filename="{ascii_name}{suffix}"; '
            f"filename*=UTF-8''{quoted}"
        )
    }


@app.get("/api/wireguard/client/{key}/configuration", dependencies=[Depends(_authed)])
async def client_config(key: str) -> PlainTextResponse:
    client = store.find(key)
    if not client:
        raise HTTPException(status_code=404, detail="Клиент не найден")
    text = render.client_conf(store.server, client, store.zone(client.get("zone_id")))
    return PlainTextResponse(text, headers=_attachment(client["name"], ".conf"))


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
    # Коррекция «L» и рамка в 4 модуля — не вкусовщина. Конфиг AmneziaWG
    # с параметрами обфускации весит под килобайт, и на «M» код уходит
    # на пару версий выше: модулей больше, каждый мельче, телефон его не
    # ловит. Рамка в 4 модуля — требование стандарта, с двумя сканеры
    # цепляют фон карточки.
    segno.make(render.client_conf(store.server, client, store.zone(client.get("zone_id"))), error="l").save(
        buf, kind="svg", scale=8, border=4, dark="#0f172a", light="#ffffff"
    )
    return Response(buf.getvalue(), media_type="image/svg+xml")


# ── Бастион: зоны доступа и апстримы ────────────────────────────────
#
# Зона отвечает на вопрос «кому куда можно», апстрим — «как мы туда
# дотягиваемся». Разделено намеренно: один туннель провайдера обычно
# обслуживает несколько зон (IPMI отдельно, management отдельно), а
# зона вполне может жить и без туннеля — на сетях, которые сервер видит
# и так.


@app.put("/api/wireguard/client/{key}/contact", dependencies=[Depends(_authed)])
async def client_contact(key: str, payload: ContactIn) -> dict[str, Any]:
    if not await store.set_contact(key, payload.telegram_id, payload.email):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return {"success": True}


@app.put("/api/wireguard/client/{key}/torrent", dependencies=[Depends(_authed)])
async def client_torrent(key: str, payload: TorrentExemptIn) -> dict[str, Any]:
    if not await store.set_torrent_exempt(key, payload.exempt):
        raise HTTPException(status_code=404, detail="Клиент не найден")
    return {"success": True}


@app.get("/api/torrent", dependencies=[Depends(_authed)])
async def torrent_get() -> dict[str, Any]:
    cfg = store.torrent or {}
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "webhookUrl": cfg.get("webhook_url") or "",
        # Секрет наружу не отдаём — только факт, что он задан.
        "webhookSecretSet": bool(cfg.get("webhook_secret")),
        "webhookConfigured": torrent.configured(cfg),
        "nodeName": cfg.get("node_name") or "",
        "blockDuration": int(cfg.get("block_duration") or 3600),
        "active": await torrent.loaded(),
        "counters": await torrent.counters(),
        "exemptCount": sum(1 for c in store.clients if c.get("torrent_exempt")),
    }


@app.put("/api/torrent", dependencies=[Depends(_authed)])
async def torrent_set(payload: TorrentConfigIn) -> dict[str, Any]:
    patch = {k: v for k, v in payload.model_dump().items() if v is not None}
    cfg = await store.set_torrent_config(patch)
    return {"success": True, "webhookConfigured": torrent.configured(cfg),
            "active": await torrent.loaded()}


@app.get("/api/zones", dependencies=[Depends(_authed)])
async def zones_list() -> list[dict[str, Any]]:
    out = []
    for zone in store.zones:
        item = dict(zone)
        item["clients"] = [
            c["id"] for c in store.clients if c.get("zone_id") == zone["id"]
        ]
        out.append(item)
    return out


@app.post("/api/zones", dependencies=[Depends(_authed)])
async def zone_create(payload: ZoneIn) -> dict[str, Any]:
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Нужно имя зоны")
    bad = [c for c in payload.cidrs if not zones.valid_cidr(c)]
    if bad:
        raise HTTPException(status_code=400, detail=f"Не подсеть: {bad[0]}")
    return await store.create_zone(
        name, payload.cidrs, upstream=payload.upstream,
        internet=payload.internet, exit=payload.exit,
    )


@app.put("/api/zones/{zone_id}", dependencies=[Depends(_authed)])
async def zone_update(zone_id: str, payload: ZonePatch) -> dict[str, Any]:
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "cidrs" in fields:
        bad = [c for c in fields["cidrs"] if not zones.valid_cidr(c)]
        if bad:
            raise HTTPException(status_code=400, detail=f"Не подсеть: {bad[0]}")
    zone = await store.update_zone(zone_id, **fields)
    if not zone:
        raise HTTPException(status_code=404, detail="Зона не найдена")
    return zone


@app.delete("/api/zones/{zone_id}", dependencies=[Depends(_authed)])
async def zone_delete(zone_id: str) -> dict[str, Any]:
    if not await store.delete_zone(zone_id):
        raise HTTPException(status_code=404, detail="Зона не найдена")
    return {"success": True}


@app.put("/api/wireguard/client/{key}/zone", dependencies=[Depends(_authed)])
async def client_set_zone(key: str, payload: ClientZoneIn) -> dict[str, Any]:
    if not await store.set_zone(key, payload.zoneId):
        raise HTTPException(status_code=404, detail="Клиент или зона не найдены")
    logger.info("зона клиента %s: %s", key, payload.zoneId or "снята")
    return {"success": True}


@app.get("/api/upstreams", dependencies=[Depends(_authed)])
async def upstreams_list() -> list[dict[str, Any]]:
    out = []
    for item in store.upstreams:
        entry = upstream.sanitize(item)
        entry["status"] = await upstream.status(item["name"])
        out.append(entry)
    return out


@app.post("/api/upstreams", dependencies=[Depends(_authed)])
async def upstream_add(payload: UpstreamIn) -> dict[str, Any]:
    name = (payload.name or "").strip()
    if not upstream.valid_name(name):
        raise HTTPException(
            status_code=400,
            detail="Имя: латиница, цифры, дефис; до 12 символов",
        )
    if "[Interface]" not in payload.conf or "[Peer]" not in payload.conf:
        raise HTTPException(status_code=400, detail="Это не конфиг WireGuard")
    item = await store.add_upstream(
        name, payload.conf, title=payload.title, cidrs=payload.cidrs
    )
    if not item:
        raise HTTPException(status_code=400, detail="Апстрим не сохранился")
    result = upstream.sanitize(item)
    result["status"] = await upstream.status(name)
    return result


@app.put("/api/upstreams/{name}", dependencies=[Depends(_authed)])
async def upstream_update(name: str, payload: UpstreamPatch) -> dict[str, Any]:
    fields = {k: v for k, v in payload.model_dump().items() if v is not None}
    item = await store.update_upstream(name, **fields)
    if not item:
        raise HTTPException(status_code=404, detail="Апстрим не найден")
    result = upstream.sanitize(item)
    result["status"] = await upstream.status(name)
    return result


@app.delete("/api/upstreams/{name}", dependencies=[Depends(_authed)])
async def upstream_delete(name: str) -> dict[str, Any]:
    if not await store.delete_upstream(name):
        raise HTTPException(status_code=404, detail="Апстрим не найден")
    return {"success": True}


@app.get("/api/journal", dependencies=[Depends(_authed)])
async def journal_list(
    limit: int = 200, client: Optional[str] = None, kind: Optional[str] = None
) -> list[dict[str, Any]]:
    """Кто, когда и откуда заходил.

    Рукопожатие говорит только «сейчас он тут». Для служебного доступа
    важнее история: когда заходил, сколько пробыл и с какого адреса —
    разбор инцидента начинается именно с этого.
    """
    return journal.select(
        store.events, limit=max(1, min(limit, journal.LIMIT)),
        client_id=client, kind=kind,
    )


@app.get("/api/topology", dependencies=[Depends(_authed)])
async def topology() -> dict[str, Any]:
    """Карта сети одним запросом: кто, через что и куда.

    Панель рисует по ней схему, поэтому связи отдаём явными рёбрами —
    иначе каждый клиент собирал бы их сам и по-своему.
    """
    stats = await awg.peer_stats()
    nodes: list[dict[str, Any]] = [{
        "id": "server",
        "kind": "server",
        "label": config.WG_INTERFACE,
        "vpn": config.VPN_PROTO,
        "endpoint": f"{config.WG_HOST}:{config.WG_CONFIG_PORT}" if config.WG_HOST else None,
        "subnet": str(render.subnet()),
    }]
    edges: list[dict[str, Any]] = []

    for item in store.upstreams:
        state = await upstream.status(item["name"])
        nodes.append({
            "id": f"upstream:{item['name']}",
            "kind": "upstream",
            "label": item.get("title") or item["name"],
            "cidrs": item.get("cidrs") or [],
            "up": state.get("up"),
            "handshakeAge": state.get("handshake_age"),
        })
        edges.append({"from": "server", "to": f"upstream:{item['name']}"})

    for zone in store.zones:
        nodes.append({
            "id": f"zone:{zone['id']}",
            "kind": "zone",
            "label": zone.get("name"),
            "cidrs": zone.get("cidrs") or [],
            "internet": bool(zone.get("internet")),
            "exit": zone.get("exit"),
        })
        if zone.get("exit") and zone["exit"] != zone.get("upstream"):
            edges.append({
                "from": f"zone:{zone['id']}",
                "to": f"upstream:{zone['exit']}",
            })
        if zone.get("upstream"):
            edges.append({
                "from": f"zone:{zone['id']}",
                "to": f"upstream:{zone['upstream']}",
            })
        else:
            # Зона без туннеля ходит через сам сервер — по его маршрутам.
            edges.append({"from": f"zone:{zone['id']}", "to": "server"})

    for client in store.clients:
        live = stats.get(client["public_key"], {})
        nodes.append({
            "id": f"client:{client['id']}",
            "kind": "client",
            "label": client.get("name"),
            "address": client.get("address"),
            "enabled": bool(client.get("enabled", True)),
            "online": bool(live.get("latest_handshake_at")),
            "lastHandshakeAt": _iso(live.get("latest_handshake_at")),
        })
        zone_id = client.get("zone_id")
        edges.append({
            "from": f"client:{client['id']}",
            "to": f"zone:{zone_id}" if zone_id else "server",
        })

    return {"nodes": nodes, "edges": edges}


# ── Резервная копия ─────────────────────────────────────────────────
#
# Ключи сервера и клиентов есть только на этой машине. Ходить за ними по
# SSH, чтобы забрать clients.json, — ровно то, чего не хочется делать
# руками на каждом из десятка серверов, поэтому копия снимается ручкой.


@app.get("/api/backup", dependencies=[Depends(_authed)])
async def backup_export() -> dict[str, Any]:
    """Состояние целиком — его забирает бот в общий бэкап."""
    return store.export_state()


@app.get("/api/backup/archive", dependencies=[Depends(_authed)])
async def backup_archive() -> Response:
    """То же, но zip'ом — чтобы скачать кнопкой из панели."""
    import io
    import json as _json
    import zipfile

    data = store.export_state()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("state.json", _json.dumps(data, ensure_ascii=False, indent=2))
        zf.writestr(
            "README.txt",
            "Резервная копия агента forestsnet.\n\n"
            f"Режим: {data['vpn']}, подсеть: {data['subnet']}.\n"
            "Внутри приватные ключи сервера и клиентов — храните как пароли.\n\n"
            "Восстановление: POST state.json на /api/backup/restore того же\n"
            "агента (режим и подсеть должны совпадать), либо из админки бота.\n",
        )
    stamp = (data.get("created_at") or "").replace(":", "-")[:19]
    name = f"{config.VPN_PROTO}-backup-{stamp or 'now'}.zip"
    return Response(
        buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@app.post("/api/backup/restore", dependencies=[Depends(_authed)])
async def backup_restore(payload: dict[str, Any]) -> dict[str, Any]:
    """Поднять состояние из копии. Всё, что было на агенте, заменяется."""
    try:
        restored = await store.import_state(payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"success": True, "clients": restored}


# ── Служебное ───────────────────────────────────────────────────────

@app.get("/api/health")
async def health() -> dict[str, Any]:
    """Публичная ручка: по ней установщик и мониторинг понимают, жив ли агент."""
    params = store.server.get("params") or {}
    return {
        "ok": True,
        "agent": __version__,
        "build": __build__,
        "repo": REPO_URL,
        "vpn": config.VPN_PROTO,
        "interface": config.WG_INTERFACE,
        "endpoint": f"{config.WG_HOST}:{config.WG_CONFIG_PORT}" if config.WG_HOST else None,
        "up": await awg.is_up(),
        "protocol": params.get("proto"),
        "header_protection": bool(params.get("header_protection_key")),
        "random_trailers": bool(params.get("random_trailers")),
        "disable_cookies": bool(params.get("disable_cookies")),
        "clients": len(store.clients),
        "shaper": config.SHAPER_ENABLED,
    }


@app.get("/api/release")
async def release() -> dict[str, Any]:
    """Совместимость: старый фронт панели спрашивал версию этой ручкой."""
    return {
        "version": __version__,
        "build": __build__,
        "repo": REPO_URL,
        "agent": "forestsnet/awg-agent",
    }


def _has(binary: str) -> bool:
    from shutil import which
    return which(binary) is not None


async def _latest_build() -> Optional[str]:
    """Короткий sha последнего коммита main в репозитории агента (через GitHub API)."""
    import json as _json
    import urllib.request

    def fetch() -> str:
        req = urllib.request.Request(
            "https://api.github.com/repos/forestsnet/awg-agent/commits/main",
            headers={"User-Agent": "awg-agent", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return (_json.load(resp).get("sha") or "")[:7]

    try:
        return await asyncio.to_thread(fetch)
    except Exception:  # noqa: BLE001
        return None


@app.get("/api/update", dependencies=[Depends(_authed)])
async def update_check() -> dict[str, Any]:
    """Есть ли новая версия. Сравниваем sha сборки с последним коммитом main."""
    latest = await _latest_build()
    available = bool(latest and __build__ not in ("dev", "") and latest != __build__)
    return {"current": __build__, "version": __version__, "latest": latest,
            "updateAvailable": available}


@app.post("/api/update", dependencies=[Depends(_authed)])
async def update_apply() -> dict[str, Any]:
    """Обновиться. Агент в контейнере: сам себя пересоздать может только через docker.sock.

    Сокет проброшен — тянем свежий образ и пересоздаём контейнер отдельным процессом
    (сам агент при этом перезапустится). Сокета нет — отдаём команду для хоста.
    """
    latest = await _latest_build()
    image = "ghcr.io/forestsnet/awg-agent:latest"
    host_cmd = "docker compose pull && docker compose up -d"
    have_sock = os.path.exists("/var/run/docker.sock") and _has("docker")
    if not have_sock:
        # Пересоздать себя с верным конфигом (env/volumes/caps/ports) агент изнутри не может —
        # это делает docker compose на хосте. Наивный docker run потерял бы PASSWORD_HASH и стейт.
        return {"applied": False, "pulled": False, "latest": latest, "hint": host_cmd,
                "detail": ("Пересоздание контейнера делается на хосте. Пробросьте /var/run/docker.sock, "
                           "чтобы агент хотя бы предзагружал образ, либо запустите команду из hint. "
                           "Проще всего — cron на хосте: " + host_cmd)}
    try:
        pull = await asyncio.create_subprocess_exec(
            "docker", "pull", image,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await pull.communicate()
        ok = pull.returncode == 0
        # Сознательно НЕ пересоздаём контейнер сами: без исходного compose это сломало бы конфиг.
        return {"applied": False, "pulled": ok, "latest": latest, "hint": host_cmd,
                "detail": (("Свежий образ загружен. " if ok else "docker pull не удался. ")
                           + "Примените пересозданием на хосте: " + host_cmd),
                "pullLog": out.decode(errors="replace")[-400:] if not ok else None}
    except Exception as e:  # noqa: BLE001
        return {"applied": False, "reason": str(e), "hint": host_cmd}


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
