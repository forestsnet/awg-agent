"""Апстримы — туннели, через которые бастион дотягивается до чужих сетей.

У владельца есть конфиги WireGuard от провайдеров: у одного за ними
IPMI серверов, у другого — своя management-сеть. Сейчас такие конфиги
лежат на отдельной машине, поднимаются руками через `wg-quick up`, и
единственное, что мешает технику добраться куда не надо, — содержимое
его собственного файла.

Агент берёт это на себя: конфиг провайдера загружается в него как есть,
поднимается своим интерфейсом (`up-<имя>`), маршруты и NAT для него
агент ставит сам, а доступ к подсетям раздаётся зонами.

Отдельно: таблицу маршрутов wg-quick мы выключаем (`Table = off`) и
прописываем маршруты руками. Иначе конфиг с `AllowedIPs = 0.0.0.0/0`
уведёт в провайдерский туннель весь трафик сервера — вместе с его
клиентами и нашим же SSH.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Optional

from . import config, zones

logger = logging.getLogger("upstream")

UPSTREAM_DIR = os.path.join(config.WG_PATH, "upstreams")
# Имя интерфейса в ядре — не длиннее 15 символов.
IFACE_PREFIX = "up-"
NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,11}$")


def iface_of(name: str) -> str:
    return f"{IFACE_PREFIX}{name}"[:15]


def conf_path(name: str) -> str:
    return os.path.join(UPSTREAM_DIR, f"{name}.conf")


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(str(name or "")))


def parse_allowed(conf: str) -> list[str]:
    """Подсети из AllowedIPs конфига — подсказка для зон.

    Оператору не нужно переписывать их руками: что провайдер разрешил,
    то и предлагаем. `0.0.0.0/0` отбрасываем — весь интернет через
    чужой туннель это не «зона», это другой способ выйти в сеть.
    """
    out: list[str] = []
    for line in conf.splitlines():
        if not line.strip().lower().startswith("allowedips"):
            continue
        for part in line.split("=", 1)[-1].split(","):
            cidr = zones.valid_cidr(part)
            if cidr and cidr not in ("0.0.0.0/0", "::/0") and cidr not in out:
                out.append(cidr)
    return out


def prepare_conf(conf: str) -> str:
    """Конфиг провайдера в том виде, в котором его поднимаем.

    Дописываем `Table = off`: маршруты ставим сами и ровно те, что
    нужны зонам.
    """
    lines = [l for l in conf.splitlines() if not l.strip().lower().startswith("table")]
    out: list[str] = []
    for line in lines:
        out.append(line)
        if line.strip().lower().startswith("[interface]"):
            out.append("Table = off")
    return "\n".join(out).rstrip() + "\n"


async def _run(*args: str, quiet: bool = False) -> tuple[bool, str]:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    out, err = await proc.communicate()
    if proc.returncode != 0:
        text = err.decode(errors="replace").strip()
        if not quiet:
            logger.warning("%s → %s", " ".join(args), text[:200])
        return False, text
    return True, out.decode(errors="replace")


async def is_up(name: str) -> bool:
    ok, _ = await _run(config.BIN, "show", iface_of(name), quiet=True)
    return ok


async def down(name: str) -> None:
    await _run("wg-quick", "down", conf_path(name), quiet=True)
    # wg-quick не уберёт интерфейс, если он поднимался другим путём.
    await _run("ip", "link", "del", iface_of(name), quiet=True)


async def up(upstream: dict[str, Any]) -> tuple[bool, str]:
    """Поднять апстрим и проложить маршруты его подсетей."""
    name = upstream["name"]
    path = conf_path(name)
    if not os.path.exists(path):
        return False, "конфиг не найден"
    await down(name)
    # wg-quick называет интерфейс по имени файла, поэтому кладём его
    # рядом под нужным именем — с префиксом, чтобы не столкнуться с
    # интерфейсом самого агента.
    iface_conf = os.path.join(UPSTREAM_DIR, f"{iface_of(name)}.conf")
    with open(path, encoding="utf-8") as fh:
        body = fh.read()
    with open(iface_conf, "w", encoding="utf-8") as fh:
        fh.write(prepare_conf(body))
    os.chmod(iface_conf, 0o600)

    ok, err = await _run("wg-quick", "up", iface_conf)
    if not ok:
        return False, err[:300]
    for cidr in upstream.get("cidrs") or []:
        await _run("ip", "route", "replace", cidr, "dev", iface_of(name), quiet=True)
    # Трафик клиентов уходит в чужой туннель с адресом самого бастиона:
    # провайдер про нашу подсеть ничего не знает и обратного маршрута у
    # него нет.
    await _run("iptables", "-t", "nat", "-C", "POSTROUTING",
               "-o", iface_of(name), "-j", "MASQUERADE", quiet=True)
    await _run("iptables", "-t", "nat", "-A", "POSTROUTING",
               "-o", iface_of(name), "-j", "MASQUERADE", quiet=True)
    logger.info("апстрим %s поднят, подсетей %d", name, len(upstream.get("cidrs") or []))
    return True, ""


async def status(name: str) -> dict[str, Any]:
    """Живой ли апстрим: хендшейк и счётчики.

    «Интерфейс поднят» ничего не значит: провайдер мог отозвать ключ, а
    wg об этом не скажет — просто не будет хендшейка.
    """
    ok, dump = await _run(config.BIN, "show", iface_of(name), "dump", quiet=True)
    if not ok:
        return {"up": False, "handshake_age": None, "rx": 0, "tx": 0}
    rows = [r for r in dump.strip().splitlines()[1:] if r]
    if not rows:
        return {"up": True, "handshake_age": None, "rx": 0, "tx": 0}
    parts = rows[0].split("\t")
    import time

    handshake = int(parts[4] or 0)
    return {
        "up": True,
        "handshake_age": int(time.time() - handshake) if handshake else None,
        "rx": int(parts[5] or 0),
        "tx": int(parts[6] or 0),
        "endpoint": parts[2] if parts[2] != "(none)" else None,
    }


async def apply(upstreams: list[dict[str, Any]]) -> None:
    """Привести апстримы к описанному состоянию."""
    os.makedirs(UPSTREAM_DIR, exist_ok=True)
    for upstream in upstreams or []:
        name = upstream.get("name")
        if not name:
            continue
        if not upstream.get("enabled", True):
            await down(name)
            continue
        if await is_up(name):
            # Уже поднят — обновляем только маршруты: состав подсетей
            # зоны мог поменяться, дёргать туннель ради этого незачем.
            for cidr in upstream.get("cidrs") or []:
                await _run("ip", "route", "replace", cidr,
                           "dev", iface_of(name), quiet=True)
            continue
        ok, err = await up(upstream)
        if not ok:
            logger.warning("апстрим %s не поднялся: %s", name, err)


def sanitize(upstream: dict[str, Any]) -> dict[str, Any]:
    """Апстрим для выдачи наружу — без содержимого конфига.

    В нём приватный ключ провайдера. Панели он не нужен ни для чего.
    """
    return {
        "name": upstream.get("name"),
        "title": upstream.get("title") or upstream.get("name"),
        "iface": iface_of(upstream.get("name") or ""),
        "cidrs": upstream.get("cidrs") or [],
        "enabled": bool(upstream.get("enabled", True)),
        "created_at": upstream.get("created_at"),
    }
