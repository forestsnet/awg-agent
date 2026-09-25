"""Торрент-блокировщик агента.

Отдельная nft-таблица `btguard` дропает UDP-контрплан торрента (DHT/uTP/tracker) по строгим
сигнатурам — в хуке forward, где виден адрес клиента в туннеле. Это работает без панели и логов.

Поверх дропа:
  * исключение — клиентам из set `exempt` торрент разрешён (их адреса добавляются в set);
  * «без бана» — клиентам из set `noban` торрент режется и попадает в отчёт, но бана нет
    (срок бана задан на сервер, выключить его можно точечно — клиенту);
  * бан — как в Remnawave: поймали на торренте, и клиент на `block_duration` секунд целиком
    теряет доступ (set `banned`, трафик режется в обе стороны). 0 — без бана, режем только
    торрент-пакеты;
  * отчёт — на дропе клиент попадает в set `offenders` (timeout = кулдаун); агент опрашивает
    set, находит клиента по адресу и шлёт вебхук В ФОРМАТЕ Remnawave (torrent_blocker.report,
    HMAC-SHA256), чтобы бот принял его без правок и мог перевести юзера в DISABLED и т.п.

Бан — по адресу клиента в туннеле, не по внешнему. Внешний у мобильных операторов общий на
сотни людей (CGNAT) и меняется со сменой сети: бан по нему бил бы по соседям и снимался бы
переключением Wi-Fi ↔ LTE. Адрес в туннеле у каждого конфига свой и не меняется.

Таблица inet, а не ip: у клиента есть и v6-адрес (ULA, зеркало v4), и при глобальном v6 у
хоста его трафик уходит в интернет через NAT66. Таблица ip его не видела — торрент по v6 шёл
мимо блокировщика, и бан снимался бы переходом на v6.

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
import re
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger("torrent")

MARK = "fsnt-torrent-blocker"          # protocol/outboundTag в отчёте — отличает наши срабатывания
OFFENDER_TIMEOUT = 3600               # сек: таймаут в set offenders и кулдаун отчёта на клиента
POLL_SECONDS = 10
MAX_BAN_SECONDS = 30 * 24 * 3600      # потолок бана: месяц
TABLE = "btguard"

# Сигнатуры ужесточены по полям (см. основной проект): наивный uTP 0x4100 ловит TURN, строгий — нет.
# @th,64,… — полезная нагрузка UDP: заголовок UDP — первые 64 бита транспортного заголовка.
_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("dht", "@th,64,96 == 0x64313a6164323a696432303a"),
    ("dht", "@th,64,96 == 0x64313a7264323a696432303a"),
    ("tracker", "@th,64,64 == 0x0000041727101980 @th,128,32 == 0x00000000"),
    ("utp", "@th,64,16 == 0x4100 @th,80,16 != 0x0000 @th,128,32 == 0x00000000 @th,192,16 == 0x0001"),
)
# (nfproto, выражение адреса, суффикс set'ов, тип элемента)
_FAMILIES: tuple[tuple[str, str, str, str], ...] = (
    ("ipv4", "ip", "4", "ipv4_addr"),
    ("ipv6", "ip6", "6", "ipv6_addr"),
)


def ban_seconds(cfg: Optional[dict[str, Any]]) -> int:
    """Срок бана из конфига: 0 — без бана."""
    try:
        value = int((cfg or {}).get("block_duration") or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, min(value, MAX_BAN_SECONDS))


def ruleset(ban: int) -> str:
    """Правила btguard. forward: исключение, бан, учёт нарушителя, дроп торрента — для v4 и v6.
    output: локальный egress (на случай, если агент рядом с локальным прокси) — просто дроп."""
    ban = max(0, int(ban or 0))
    out = [
        f"table inet {TABLE}",
        f"delete table inet {TABLE}",
        f"table inet {TABLE} {{",
    ]
    for _, _, n, etype in _FAMILIES:
        out += [
            f"    set exempt{n} {{ type {etype}; flags interval; }}",
            f"    set noban{n} {{ type {etype}; flags interval; }}",
            f"    set offenders{n} {{ type {etype}; flags dynamic,timeout; }}",
            f"    set banned{n} {{ type {etype}; flags dynamic,timeout; }}",
        ]
    out += [
        "    counter dht { }",
        "    counter utp { }",
        "    counter tracker { }",
        "    counter banned { }",
        "    chain forward {",
        "        type filter hook forward priority filter - 5; policy accept;",
    ]
    for _, fam, n, _ in _FAMILIES:
        out.append(f"        {fam} saddr @exempt{n} return")
    for _, fam, n, _ in _FAMILIES:
        out.append(f'        {fam} saddr @banned{n} counter name "banned" drop')
        out.append(f"        {fam} daddr @banned{n} drop")
    for proto, fam, n, _ in _FAMILIES:
        for name, sig in _SIGNATURES:
            upd = f"update @offenders{n} {{ {fam} saddr timeout {OFFENDER_TIMEOUT}s }}"
            if ban:
                # «Без бана» у клиента: пакет режем и учитываем для отчёта, но в banned не кладём.
                # Правило раньше общего — первый drop заканчивает разбор.
                out.append(
                    f"        meta nfproto {proto} {fam} saddr @noban{n} meta l4proto udp {sig} "
                    f'{upd} counter name "{name}" drop'
                )
                upd += f" update @banned{n} {{ {fam} saddr timeout {ban}s }}"
            out.append(
                f'        meta nfproto {proto} meta l4proto udp {sig} {upd} counter name "{name}" drop'
            )
    out += [
        "    }",
        "    chain output {",
        "        type filter hook output priority filter - 5; policy accept;",
    ]
    for name, sig in _SIGNATURES:
        out.append(f'        meta l4proto udp {sig} counter name "{name}" drop')
    out += ["    }", "}"]
    return "\n".join(out) + "\n"


async def _nft(*args: str, stdin: Optional[str] = None) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "nft", *args,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        # Без утилиты nft блокировщик не работает — но и ручки агента падать не должны.
        return 127, "nft не установлен"
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


def client_ips(client: dict[str, Any]) -> list[str]:
    """Адреса клиента в туннеле: v4 и его v6-зеркало (если v6 в туннеле включён)."""
    ip4 = _addr_ip(client.get("address"))
    if not ip4:
        return []
    ips = [ip4]
    try:
        from . import render

        ip6 = render.address6_for(ip4)
    except Exception:  # noqa: BLE001
        ip6 = ""
    if ip6:
        ips.append(str(ipaddress.ip_address(ip6)))
    return ips


def _family(ip: str) -> str:
    return "6" if ":" in ip else "4"


async def available() -> bool:
    rc, _ = await _nft("--version")
    return rc == 0


async def loaded() -> bool:
    rc, _ = await _nft("list", "table", "inet", TABLE)
    return rc == 0


# Какие правила сейчас в ядре. apply() зовётся на каждое изменение клиентов (создание,
# удаление, лимиты), и пересборка таблицы каждый раз обнуляла бы все баны: новый конфиг на
# сервере — и все, кого забанили, снова качают.
_applied_rules: Optional[str] = None


async def apply(clients: list[dict[str, Any]], cfg: Optional[dict[str, Any]] = None) -> bool:
    """Поднять btguard (или пересобрать, если правила поменялись) и заполнить exempt."""
    global _applied_rules
    ban = ban_seconds(cfg)
    rules = ruleset(ban)
    if rules != _applied_rules or not await loaded():
        # Сменился срок бана — действующие баны переживают пересборку (с остатком срока).
        kept = await banned() if await loaded() else {}
        # Сборка до 25.09 держала таблицу ip btguard — в том же пространстве имён её надо снять.
        await _nft("delete", "table", "ip", TABLE)
        rc, out = await _nft("-f", "-", stdin=rules)
        if rc != 0:
            _applied_rules = None
            logger.error("btguard не загрузился: %s", out.strip())
            return False
        _applied_rules = rules
        if ban:
            for ip, left in kept.items():
                if left > 0:
                    await _nft("add", "element", "inet", TABLE, f"banned{_family(ip)}",
                               "{ %s timeout %ds }" % (ip, min(left, ban)))
    await sync_exempt(clients)
    return True


def _elements(raw: str) -> set[str]:
    """Адреса из `nft list set` (с таймаутами и без)."""
    m = re.search(r"elements = \{([^}]*)\}", raw, re.S)
    if not m:
        return set()
    out = set()
    for item in m.group(1).split(","):
        token = item.strip().split(" ")[0].strip()
        if token:
            out.add(token)
    return out


async def _set_elements(name: str) -> set[str]:
    rc, raw = await _nft("list", "set", "inet", TABLE, name)
    return _elements(raw) if rc == 0 else set()


async def sync_exempt(clients: list[dict[str, Any]]) -> None:
    """Привести set'ы exempt и noban в соответствие флагам клиентов.

    Исключённым и «без бана» — снять действующий бан: флаг ставят как раз затем,
    чтобы человек не сидел без связи.
    """
    if not await loaded():
        return
    changed = False
    for setname, flag in (("exempt", "torrent_exempt"), ("noban", "torrent_noban")):
        want: dict[str, set[str]] = {"4": set(), "6": set()}
        for c in clients:
            if c.get(flag):
                for ip in client_ips(c):
                    want[_family(ip)].add(ip)
        for n in ("4", "6"):
            have = await _set_elements(f"{setname}{n}")
            for ip in want[n] - have:
                await _nft("add", "element", "inet", TABLE, f"{setname}{n}", "{ %s }" % ip)
                await _nft("delete", "element", "inet", TABLE, f"banned{n}", "{ %s }" % ip)
            for ip in have - want[n]:
                await _nft("delete", "element", "inet", TABLE, f"{setname}{n}", "{ %s }" % ip)
            changed = changed or want[n] != have
    if changed:
        logger.info(
            "btguard: исключений %d, без бана %d",
            sum(1 for c in clients if c.get("torrent_exempt")),
            sum(1 for c in clients if c.get("torrent_noban")),
        )


async def teardown() -> None:
    """Снять btguard (torrent выключен в конфиге)."""
    global _applied_rules
    _applied_rules = None
    await _nft("delete", "table", "inet", TABLE)
    await _nft("delete", "table", "ip", TABLE)


async def counters() -> dict[str, int]:
    rc, raw = await _nft("-j", "list", "table", "inet", TABLE)
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
    return (await _set_elements("offenders4")) | (await _set_elements("offenders6"))


_TIMEOUT_RE = re.compile(r"(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:\d+ms)?$")


def _seconds(text: str) -> int:
    m = _TIMEOUT_RE.match(text.strip())
    if not m:
        return 0
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


async def banned() -> dict[str, int]:
    """Кто сейчас в бане: адрес → сколько секунд осталось."""
    out: dict[str, int] = {}
    for n in ("4", "6"):
        rc, raw = await _nft("list", "set", "inet", TABLE, f"banned{n}")
        if rc != 0:
            continue
        m = re.search(r"elements = \{([^}]*)\}", raw, re.S)
        if not m:
            continue
        for item in m.group(1).split(","):
            parts = item.split()
            if not parts:
                continue
            left = 0
            if "expires" in parts:
                i = parts.index("expires")
                if i + 1 < len(parts):
                    left = _seconds(parts[i + 1])
            out[parts[0]] = left
    return out


async def unban(client: dict[str, Any]) -> bool:
    """Снять бан с клиента досрочно (оба адреса). True — был в бане."""
    was = False
    current = await banned()
    for ip in client_ips(client):
        if ip in current:
            was = True
            await _nft("delete", "element", "inet", TABLE, f"banned{_family(ip)}", "{ %s }" % ip)
    return was


# ── вебхук в формате Remnawave ──────────────────────────────────────

def _report(cfg: dict[str, Any], client: dict[str, Any], addr: str) -> dict[str, Any]:
    ts = datetime.now(timezone.utc)
    # «Без бана» у клиента: правило noban не банит — и отчёт не должен
    # обещать бан, иначе бот напишет человеку «доступ закрыт на час».
    dur = 0 if client.get("torrent_noban") else ban_seconds(cfg)
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
                    # blockDuration — срок бана клиента; 0 — бана нет, режутся только
                    # торрент-пакеты (willUnblockAt тогда пустой).
                    "blocked": True, "ip": addr, "blockDuration": dur,
                    "willUnblockAt": iso(ts + timedelta(seconds=dur)) if dur else None,
                    "userId": user_id, "processedAt": iso(ts),
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


def _by_ip(clients: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for c in clients:
        for ip in client_ips(c):
            out[ip] = c
    return out


async def watch(store: Any) -> None:
    """Опрос offenders -> отчёт по новым клиентам. store даёт clients и torrent-конфиг."""
    seen: dict[str, float] = {}
    while True:
        await asyncio.sleep(POLL_SECONDS)
        try:
            cfg = store.torrent or {}
            if not await loaded():
                continue
            offenders = await _offenders()
            now = time.time()
            index = _by_ip(store.clients)
            for ip in offenders:
                client = index.get(ip)
                # Кулдаун — на клиента, а не на адрес: v4 и v6 одного клиента — один отчёт.
                key = client.get("id") if client else ip
                if now - seen.get(key, 0) < OFFENDER_TIMEOUT:
                    continue
                seen[key] = now
                if not client:
                    logger.info("btguard: торрент с %s (клиент не сопоставлен)", ip)
                    continue
                if client.get("torrent_exempt"):
                    continue
                await store.record_torrent(client, ip)
                if configured(cfg):
                    # Отчёт — в отдельном потоке: urllib синхронный, а три попытки по 10 с
                    # останавливали бы весь агент (и ручки для бота) на полминуты.
                    st = await asyncio.to_thread(_send, cfg, _report(cfg, client, ip))
                    logger.info("btguard: торрент у %s (%s) -> вебхук %s", client.get("name"), ip, st)
                else:
                    logger.info("btguard: торрент у %s (%s) — вебхук не настроен", client.get("name"), ip)
            # чистим память о давних срабатываниях
            for key in list(seen):
                if now - seen[key] > OFFENDER_TIMEOUT:
                    del seen[key]
        except Exception:  # noqa: BLE001
            logger.exception("torrent watch: сбой тика")
