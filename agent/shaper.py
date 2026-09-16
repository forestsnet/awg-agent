"""Ограничение скорости на клиента.

Лимит трафика отвечает на вопрос «сколько всего», шейпер — «как быстро».
Делает это `tc` прямо на wg-интерфейсе:

  * скачивание (сервер → клиент) — классы HTB на исходящем направлении,
    фильтр по адресу назначения;
  * отдача (клиент → сервер) — policer на ingress-качдиске, фильтр по
    адресу источника. На входящем направлении очередей нет, лишнее
    просто отбрасывается — это и есть polic­ing.

Правила не правим по одному, а перестраиваем целиком: клиентов десятки,
перестройка занимает миллисекунды, а diff-логика на tc — это способ
однажды забыть снять чужое правило и не понять, почему у клиента
скорость чужого тарифа.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

from . import config

logger = logging.getLogger("shaper")

# Класс по умолчанию — для всех, кому скорость не ограничивали. 0xFFFF
# выбран не случайно: номер класса берётся из младших 16 бит адреса, а
# такой адрес в подсети не выдаётся (это её широковещательный). С
# «красивым» 9999 клиент 10.8.39.15 попал бы в чужой класс.
DEFAULT_CLASSID = 0xFFFF


async def _run(*args: str, quiet: bool = False) -> bool:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        if not quiet:
            logger.warning("%s → %s", " ".join(args), err.decode(errors="replace").strip()[:200])
        return False
    return True


def class_id(address: str) -> int:
    """Номер класса из адреса клиента.

    Берём хостовую часть: в /24 она уникальна, а номер должен быть
    стабильным — иначе после перестройки клиент попадёт в чужой класс.
    """
    try:
        return int(ipaddress.ip_address(address.split("/")[0])) & 0xFFFF
    except ValueError:
        return 0


def burst_bytes(rate_bps: int) -> int:
    """Всплеск ≈ 40 мс трафика, но не меньше 32 КБ.

    Меньше — и мелкие пачки пакетов режутся на ровном месте: TCP не
    успевает разогнаться, а человек видит «медленно» на скорости, которая
    формально выдана.
    """
    return max(rate_bps // 8 // 25, 32 * 1024)


async def _reset() -> None:
    # Ошибки глушим: качдиска может и не быть, это нормальный случай.
    await _run("tc", "qdisc", "del", "dev", config.WG_INTERFACE, "root", quiet=True)
    await _run("tc", "qdisc", "del", "dev", config.WG_INTERFACE, "ingress", quiet=True)


async def apply(clients: list[dict[str, Any]]) -> None:
    """Перестроить правила под текущий список клиентов."""
    if not config.SHAPER_ENABLED:
        return

    limited = [
        c for c in clients
        if c.get("enabled", True) and int(c.get("rate_bps") or 0) > 0 and c.get("address")
    ]
    await _reset()
    if not limited:
        # Никому не ограничивали — правил нет вовсе, ядро не тратит на
        # нас ни такта.
        return

    iface = config.WG_INTERFACE
    # quantum задаём руками: без него htb ругается на класс по умолчанию
    # («quantum is big») и считает его сам от гигабитной скорости.
    ok = await _run("tc", "qdisc", "add", "dev", iface, "root", "handle", "1:",
                    "htb", "default", str(DEFAULT_CLASSID))
    if not ok:
        logger.warning("шейпер не включился: интерфейс %s не принял qdisc", iface)
        return
    await _run("tc", "class", "add", "dev", iface, "parent", "1:",
               "classid", f"1:{DEFAULT_CLASSID}", "htb", "rate", "10gbit", "quantum", "200000")
    await _run("tc", "qdisc", "add", "dev", iface, "handle", "ffff:", "ingress")

    for client in limited:
        rate = int(client["rate_bps"])
        cid = class_id(client["address"])
        if not cid or cid == DEFAULT_CLASSID:
            continue
        addr = client["address"].split("/")[0]
        burst = burst_bytes(rate)

        # Скачивание: свой класс и честная очередь внутри него, чтобы
        # одна тяжёлая закачка не затыкала остальные соединения клиента.
        await _run("tc", "class", "add", "dev", iface, "parent", "1:", "classid", f"1:{cid}",
                   "htb", "rate", f"{rate}bit", "ceil", f"{rate}bit", "burst", f"{burst}b")
        await _run("tc", "qdisc", "add", "dev", iface, "parent", f"1:{cid}",
                   "handle", f"{cid}:", "sfq", "perturb", "10")
        await _run("tc", "filter", "add", "dev", iface, "parent", "1:", "protocol", "ip",
                   "prio", "1", "u32", "match", "ip", "dst", f"{addr}/32", "flowid", f"1:{cid}")

        # Отдача: очередей на входе нет, поэтому просто режем лишнее.
        await _run("tc", "filter", "add", "dev", iface, "parent", "ffff:", "protocol", "ip",
                   "prio", "1", "u32", "match", "ip", "src", f"{addr}/32",
                   "police", "rate", f"{rate}bit", "burst", f"{burst}b", "drop", "flowid", ":1")

    logger.info("шейпер: правил на %d клиент(ов)", len(limited))
