"""Тонкая обёртка над awg / awg-quick.

Всё общение с ядром — здесь. Ровно две вещи, которые стоит помнить:

1. Изменения применяем через `awg syncconf`, а не перезапуском
   интерфейса: syncconf накатывает разницу, живые сессии остальных
   клиентов при этом не рвутся. `awg-quick down/up` на каждого нового
   клиента — это отключение всех.
2. `awg show dump` кэшируем на секунду: список открывают часто, а
   счётчики трафика за это время не меняются настолько, чтобы ради них
   дёргать бинарник на каждый запрос.
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import time
from typing import Any, Optional

from . import config

logger = logging.getLogger("awg")


class AwgError(RuntimeError):
    pass


async def run(*args: str, stdin: Optional[str] = None, check: bool = True) -> str:
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate(stdin.encode() if stdin is not None else None)
    if check and proc.returncode != 0:
        raise AwgError(
            f"{' '.join(args)} → {proc.returncode}: {err.decode(errors='replace').strip()[:300]}"
        )
    return out.decode(errors="replace")


# ── Ключи ───────────────────────────────────────────────────────────

async def genkey() -> str:
    return (await run("awg", "genkey")).strip()


async def pubkey(private_key: str) -> str:
    return (await run("awg", "pubkey", stdin=private_key + "\n")).strip()


async def genpsk() -> str:
    return (await run("awg", "genpsk")).strip()


async def keypair() -> tuple[str, str]:
    private = await genkey()
    return private, await pubkey(private)


# ── Состояние интерфейса ────────────────────────────────────────────

_dump_cache: dict[str, Any] = {"at": 0.0, "peers": {}}


async def is_up() -> bool:
    try:
        await run("awg", "show", config.WG_INTERFACE, "dump")
        return True
    except AwgError:
        return False


def _parse_dump(raw: str) -> dict[str, dict[str, Any]]:
    """Разбор `awg show <iface> dump`.

    Первая строка — сам интерфейс, дальше по строке на пира:
    pubkey, psk, endpoint, allowed-ips, последний хендшейк, rx, tx,
    keepalive.
    """
    peers: dict[str, dict[str, Any]] = {}
    for line in raw.strip().split("\n")[1:]:
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        handshake = int(parts[4] or 0)
        peers[parts[0]] = {
            "endpoint": None if parts[2] in ("(none)", "") else parts[2],
            "allowed_ips": parts[3],
            "latest_handshake_at": handshake or None,
            "transfer_rx": int(parts[5] or 0),
            "transfer_tx": int(parts[6] or 0),
        }
    return peers


async def peer_stats(force: bool = False) -> dict[str, dict[str, Any]]:
    now = time.monotonic()
    if not force and now - float(_dump_cache["at"]) < config.STATS_TTL_SECONDS:
        return _dump_cache["peers"]  # type: ignore[return-value]
    try:
        raw = await run("awg", "show", config.WG_INTERFACE, "dump")
        peers = _parse_dump(raw)
    except AwgError:
        # Интерфейс не поднят — это не ошибка запроса списка: клиенты в
        # базе есть, просто счётчиков по ним пока нет.
        peers = {}
    _dump_cache["at"] = now
    _dump_cache["peers"] = peers
    return peers


def drop_stats_cache() -> None:
    _dump_cache["at"] = 0.0


# ── Применение конфига ──────────────────────────────────────────────

async def sync() -> None:
    """Накатить текущий файл конфига на живой интерфейс."""
    if not await is_up():
        return
    stripped = await run("awg-quick", "strip", config.CONF_PATH)
    fd, path = tempfile.mkstemp(prefix="awgsync-", suffix=".conf")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(stripped)
        await run("awg", "syncconf", config.WG_INTERFACE, path)
    finally:
        os.unlink(path)
    drop_stats_cache()


async def up() -> None:
    if await is_up():
        return
    await run("awg-quick", "up", config.CONF_PATH)
    drop_stats_cache()


async def down() -> None:
    if not await is_up():
        return
    await run("awg-quick", "down", config.CONF_PATH, check=False)
    drop_stats_cache()
