"""Торрент-блокировщик агента.

Отдельная nft-таблица `btguard` дропает UDP-контрплан торрента (DHT/uTP/tracker) по строгим
сигнатурам — в хуке forward, где виден адрес клиента в туннеле. Это работает без панели и логов.

Две вещи поверх дропа:
  * исключение — клиентам из set `@exempt` торрент разрешён (их адрес добавляется в set);
  * отчёт — на дропе клиент попадает в set `@offenders` (timeout = кулдаун); агент опрашивает
    set, находит клиента по адресу и шлёт вебхук В ФОРМАТЕ Remnawave (torrent_blocker.report,
    HMAC-SHA256), чтобы бот принял его без правок и мог перевести юзера в DISABLED и т.п.

Почему set, а не kernel-лог: агент живёт в контейнере, доступа к /dev/kmsg у него нет, а nft
через NET_ADMIN — есть. Опрос set не зависит ни от ротации логов, ни от journald.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import subprocess
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger("torrent")

MARK = "fsnt-torrent-blocker"          # protocol/outboundTag в отчёте — отличает наши срабатывания
OFFENDER_TIMEOUT = 3600               # сек: и таймаут в nft-set, и кулдаун отчёта на клиента
POLL_SECONDS = 10

# nft-правила btguard. forward: клиентский торрент (виден tunnel-src) — исключение, учёт нарушителя,
# дроп. output: локальный egress (на случай, если агент рядом с локальным прокси) — просто дроп.
# Сигнатуры ужесточены по полям (см. основной проект): наивный uTP 0x4100 ловит TURN, строгий — нет.
_RULESET = r"""
table ip btguard
delete table ip btguard
table ip btguard {
    set exempt {
        type ipv4_addr
        flags interval
    }
    set offenders {
        type ipv4_addr
        flags timeout
    }
    counter dht     { }
    counter utp     { }
    counter tracker { }

    chain forward {
        type filter hook forward priority filter - 5; policy accept;
        ip saddr @exempt return
        meta l4proto udp @th,64,96 == 0x64313a6164323a696432303a update @offenders { ip saddr timeout %ds } counter name "dht" drop
        meta l4proto udp @th,64,96 == 0x64313a7264323a696432303a update @offenders { ip saddr timeout %ds } counter name "dht" drop
        meta l4proto udp @th,64,64 == 0x0000041727101980 @th,128,32 == 0x00000000 update @offenders { ip saddr timeout %ds } counter name "tracker" drop
        meta l4proto udp @th,64,16 == 0x4100 @th,80,16 != 0x0000 @th,128,32 == 0x00000000 @th,192,16 == 0x0001 update @offenders { ip saddr timeout %ds } counter name "utp" drop
    }
    chain output {
        type filter hook output priority filter - 5; policy accept;
        meta l4proto udp @th,64,96 == 0x64313a6164323a696432303a counter name "dht" drop
        meta l4proto udp @th,64,96 == 0x64313a7264323a696432303a counter name "dht" drop
        meta l4proto udp @th,64,64 == 0x0000041727101980 @th,128,32 == 0x00000000 counter name "tracker" drop
        meta l4proto udp @th,64,16 == 0x4100 @th,80,16 != 0x0000 @th,128,32 == 0x00000000 @th,192,16 == 0x0001 counter name "utp" drop
    }
}
"""


async def _nft(*args: str, stdin: Optional[str] = None) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        "nft", *args,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    out, _ = await proc.communicate(stdin.encode() if stdin is not None else None)
    return proc.returncode or 0, out.decode(errors="replace")


def _addr_ip(address: Optional[str]) -> Optional[str]:
    """Из "10.8.0.5/32" или "10.8.0.5, fd::5" берём первый IPv4."""
    if not address:
        return None
    for part in str(address).replace(",", " ").split():
        host = part.split("/")[0].strip()
        try:
            if isinstance(ipaddress.ip_address(host), ipaddress.IPv4Address):
                return host
        except ValueError:
            continue
    return None


async def loaded() -> bool:
    rc, _ = await _nft("list", "table", "ip", "btguard")
    return rc == 0


async def apply(clients: list[dict[str, Any]]) -> bool:
    """Поднять/пересобрать btguard и заполнить @exempt адресами клиентов-исключений."""
    rc, out = await _nft("-f", "-", stdin=_RULESET % ((OFFENDER_TIMEOUT,) * 4))
    if rc != 0:
        logger.error("btguard не загрузился: %s", out.strip())
        return False
    await sync_exempt(clients)
    return True


async def sync_exempt(clients: list[dict[str, Any]]) -> None:
    """Привести @exempt в соответствие клиентам с torrent_exempt=True."""
    if not await loaded():
        return
    want = set()
    for c in clients:
        if c.get("torrent_exempt"):
            ip = _addr_ip(c.get("address"))
            if ip:
                want.add(ip)
    rc, raw = await _nft("list", "set", "ip", "btguard", "exempt")
    have = set()
    if rc == 0:
        import re
        m = re.search(r"elements = \{([^}]*)\}", raw, re.S)
        if m:
            have = {x.strip() for x in m.group(1).split(",") if x.strip()}
    for ip in want - have:
        await _nft("add", "element", "ip", "btguard", "exempt", "{ %s }" % ip)
    for ip in have - want:
        await _nft("delete", "element", "ip", "btguard", "exempt", "{ %s }" % ip)
    if want != have:
        logger.info("btguard: исключений %d", len(want))


async def teardown() -> None:
    """Снять btguard (torrent выключен в конфиге)."""
    await _nft("delete", "table", "ip", "btguard")


async def counters() -> dict[str, int]:
    rc, raw = await _nft("-j", "list", "table", "ip", "btguard")
    if rc != 0:
        return {}
    try:
        data = json.loads(raw)
    except ValueError:
        return {}
    res = {}
    for item in data.get("nftables", []):
        c = item.get("counter")
        if isinstance(c, dict) and "name" in c and "packets" in c:
            res[c["name"]] = c["packets"]
    return res


async def _offenders() -> set[str]:
    rc, raw = await _nft("list", "set", "ip", "btguard", "offenders")
    if rc != 0:
        return set()
    import re
    ips = set()
    for m in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3})", raw.split("elements", 1)[-1]):
        ips.add(m.group(1))
    return ips


# ── вебхук в формате Remnawave ──────────────────────────────────────

def _report(cfg: dict[str, Any], client: dict[str, Any], addr: str) -> dict[str, Any]:
    ts = datetime.now(timezone.utc)
    dur = int(cfg.get("block_duration") or OFFENDER_TIMEOUT)
    unblock = ts + timedelta(seconds=dur)
    def iso(t): return t.isoformat().replace("+00:00", "Z")
    user_id = str(client.get("telegram_id") or client.get("id") or addr)
    return {
        "scope": "torrent_blocker",
        "event": "torrent_blocker.report",
        "timestamp": iso(ts),
        "data": {
            "node": {"name": cfg.get("node_name") or "awg-agent"},
            "user": {
                "id": user_id,
                "username": client.get("name") or addr,
                "telegramId": client.get("telegram_id"),
                "email": client.get("email"),
            },
            "report": {
                "actionReport": {
                    "blocked": True, "ip": addr, "blockDuration": dur,
                    "willUnblockAt": iso(unblock), "userId": user_id, "processedAt": iso(ts),
                },
                "xrayReport": {
                    "email": client.get("name") or user_id, "level": 0,
                    "protocol": MARK, "network": "udp",
                    "source": addr, "destination": None,
                    "routeTarget": "btguard", "originalTarget": None,
                    "inboundTag": "wireguard", "inboundName": None, "inboundLocal": None,
                    "outboundTag": MARK, "ts": int(ts.timestamp()),
                },
            },
        },
    }


def _send(cfg: dict[str, Any], payload: dict[str, Any]) -> str:
    body = json.dumps(payload, ensure_ascii=False).encode()
    sig = hmac.new(str(cfg["webhook_secret"]).encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        cfg["webhook_url"], data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Remnawave-Signature": sig,
            "X-Remnawave-Timestamp": payload["timestamp"],
            "User-Agent": "Remnawave",
        },
    )
    for attempt in (1, 2, 3):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return f"HTTP {resp.status}"
        except Exception as e:  # noqa: BLE001
            if attempt == 3:
                return f"ошибка: {e}"
            time.sleep(3)
    return "?"


def configured(cfg: dict[str, Any]) -> bool:
    return bool(cfg and cfg.get("webhook_url") and cfg.get("webhook_secret"))


async def watch(store: Any) -> None:
    """Опрос @offenders -> отчёт по новым клиентам. store даёт clients и torrent-конфиг."""
    seen: dict[str, float] = {}
    while True:
        await asyncio.sleep(POLL_SECONDS)
        try:
            cfg = store.torrent or {}
            if not await loaded():
                continue
            offenders = await _offenders()
            now = time.time()
            for ip in offenders:
                if now - seen.get(ip, 0) < OFFENDER_TIMEOUT:
                    continue
                seen[ip] = now
                client = next((c for c in store.clients if _addr_ip(c.get("address")) == ip), None)
                if not client:
                    logger.info("btguard: торрент с %s (клиент не сопоставлен)", ip)
                    continue
                if client.get("torrent_exempt"):
                    continue
                await store.record_torrent(client, ip)
                if configured(cfg):
                    st = _send(cfg, _report(cfg, client, ip))
                    logger.info("btguard: торрент у %s (%s) -> вебхук %s", client.get("name"), ip, st)
                else:
                    logger.info("btguard: торрент у %s (%s) — вебхук не настроен", client.get("name"), ip)
            # чистим память о выбывших из set
            for ip in list(seen):
                if ip not in offenders and now - seen[ip] > OFFENDER_TIMEOUT:
                    del seen[ip]
        except Exception:  # noqa: BLE001
            logger.exception("torrent watch: сбой тика")
