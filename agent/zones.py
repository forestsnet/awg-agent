"""Зоны доступа: кому из клиентов куда можно.

Задача из жизни. У владельца есть VPN-конфиги провайдеров с доступом к
IPMI серверов, и есть три техника. Выдать им один общий конфиг — значит
отдать IPMI всем троим и навсегда. Выдать разные — не проблема, проблема
в том, что «разные» обычно означает лишь разный список `AllowedIPs` в
файле у клиента. Это не ограничение, а просьба: файл лежит у человека,
и дописать туда чужую подсеть — одна строка.

Поэтому решение живёт на сервере. Зона — это имя, список подсетей и,
если нужно, апстрим-туннель, через который в эти подсети ходят. Клиент
привязан к зоне; в его конфиг уезжают ровно её подсети, а на сервере
стоят правила по адресу источника. Перепишет файл — ничего не получит.

Отдельно важно: подсети зон закрыты и для клиентов БЕЗ зоны. Обычный
человек, который просто пользуется VPN, не должен видеть служебные сети
только потому, что сервер до них дотягивается.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any, Iterable, Optional

from . import config, upstream

logger = logging.getLogger("zones")

# Своя цепочка: чужие правила (docker, fail2ban) не трогаем, свои —
# всегда можем снести целиком и собрать заново.
CHAIN = "FSNT-ZONES"

# Таблицы маршрутов для «выходной ноды»: обычный трафик техника уходит
# не через адрес бастиона, а через выбранный туннель. Нужно не для
# красоты — техник лезет на клиентские машины для диагностики, и
# светить туда свой домашний адрес (и адрес бастиона заодно) не надо.
#
# Правила висят в своём диапазоне приоритетов: чужие политики (docker,
# vpn провайдера) не трогаем, свои — сносим целиком и ставим заново.
RULE_PRIORITY_BASE = 17000
TABLE_BASE = 170

# Ставили ли мы политики хоть раз: у обычного сервера их нет и не
# будет, и дёргать `ip rule` на каждое изменение клиента незачем.
_routing_installed = False


async def _run(*args: str, quiet: bool = False) -> bool:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, err = await proc.communicate()
    if proc.returncode != 0:
        if not quiet:
            logger.warning(
                "%s → %s", " ".join(args), err.decode(errors="replace").strip()[:200]
            )
        return False
    return True


def valid_cidr(value: str) -> Optional[str]:
    """Нормализованная подсеть или None.

    Принимаем и одиночный адрес: «10.30.247.190» — это /32, и так
    оператору привычнее, чем писать маску руками.
    """
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        return None
    return str(net)


def normalize_cidrs(values: Iterable[Any]) -> list[str]:
    out: list[str] = []
    for value in values or []:
        cidr = valid_cidr(value)
        if cidr and cidr not in out:
            out.append(cidr)
    return out


def protected_cidrs(zones: list[dict[str, Any]]) -> list[str]:
    """Всё, что вообще закрыто зонами.

    Нужно не только для владельцев зон: клиент без зоны тоже не должен
    попадать в служебные сети. Считаем объединение один раз и правим
    правила по нему.
    """
    out: list[str] = []
    for zone in zones or []:
        for cidr in zone.get("cidrs") or []:
            if cidr not in out:
                out.append(cidr)
    return out


def zone_of(client: dict[str, Any], zones: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    zone_id = client.get("zone_id")
    if not zone_id:
        return None
    for zone in zones or []:
        if zone.get("id") == zone_id:
            return zone
    return None


def exit_of(zone: Optional[dict[str, Any]]) -> Optional[str]:
    """Через какой туннель у зоны уходит обычный трафик.

    Пусто — через сам бастион, как было. Имя апстрима — значит наружу
    техник выходит его адресом.
    """
    if not zone or not zone.get("internet"):
        return None
    return zone.get("exit") or None


def client_allowed_ips(zone: Optional[dict[str, Any]], default: str) -> str:
    """Что писать клиенту в AllowedIPs.

    Без зоны — как было (обычно весь интернет). С зоной и без интернета
    — только её подсети: маршрутизировать остальное в туннель незачем,
    сервер это всё равно не пропустит, а у человека перестанет работать
    интернет с непонятной причиной.
    """
    if not zone:
        return default
    cidrs = list(zone.get("cidrs") or [])
    if zone.get("internet"):
        return default
    return ", ".join(cidrs) if cidrs else default


async def _reset_routing(upstreams: list[dict[str, Any]]) -> None:
    """Снять свои правила политики и очистить свои таблицы."""
    # Правила удаляем по приоритету: так не заденем чужие, даже если
    # адреса совпали.
    for index in range(len(upstreams) + 8):
        priority = RULE_PRIORITY_BASE + index
        # На один приоритет правил бывает несколько (переживший
        # перезапуск дубль), но цикл ограничен: `ip` на некоторых
        # системах возвращает ноль даже когда удалять нечего, и
        # «пока удаляется» превращалось в вечный цикл.
        for _ in range(4):
            if not await _run("ip", "rule", "del", "priority", str(priority), quiet=True):
                break
    for index in range(len(upstreams) + 8):
        await _run("ip", "route", "flush", "table", str(TABLE_BASE + index), quiet=True)


async def _apply_routing(
    clients: list[dict[str, Any]],
    zones: list[dict[str, Any]],
    upstreams: list[dict[str, Any]],
) -> int:
    """Развести обычный трафик техников по выходным туннелям."""
    global _routing_installed
    table_of: dict[str, int] = {
        item["name"]: TABLE_BASE + i for i, item in enumerate(upstreams or [])
    }
    plan = []
    for client in clients:
        address = str(client.get("address") or "").split("/")[0]
        name = exit_of(zone_of(client, zones))
        if address and name and name in table_of:
            plan.append((address, name, table_of[name]))
    if not plan and not _routing_installed:
        # Выходных нод не было и нет: обычный сервер про политики
        # маршрутизации знать не должен вовсе.
        return 0

    await _reset_routing(upstreams)
    _routing_installed = bool(plan)
    routed = 0
    priority = RULE_PRIORITY_BASE
    for address, name, table in plan:
        iface = upstream.iface_of(name)
        # default в своей таблице: основную не трогаем вовсе, иначе
        # туда же уедет и трафик самого сервера.
        await _run("ip", "route", "replace", "default", "dev", iface,
                   "table", str(table), quiet=True)
        await _run("ip", "rule", "add", "from", f"{address}/32",
                   "lookup", str(table), "priority", str(priority))
        priority += 1
        routed += 1
    if routed:
        logger.info("выходная нода: %d техник(ов) выходят через туннель", routed)
    return routed


async def _reset() -> None:
    iface = config.WG_INTERFACE
    # Порядок важен: сначала снимаем ссылку из FORWARD, потом чистим и
    # удаляем саму цепочку — занятую iptables удалить не даст.
    await _run("iptables", "-D", "FORWARD", "-i", iface, "-j", CHAIN, quiet=True)
    await _run("iptables", "-F", CHAIN, quiet=True)
    await _run("iptables", "-X", CHAIN, quiet=True)


# Ставили ли мы уже цепочку. Нужно, чтобы обычный сервер без зон вообще
# не дёргал iptables: у него их нет и не будет, а лишние вызовы — это
# лишние предупреждения в логе на каждое изменение клиента.
_installed = False


async def apply(
    clients: list[dict[str, Any]],
    zones: list[dict[str, Any]],
    upstreams: Optional[list[dict[str, Any]]] = None,
) -> None:
    """Перестроить правила зон под текущее состояние."""
    global _installed
    await _apply_routing(clients, zones, upstreams or [])
    protected = protected_cidrs(zones)
    if not protected and not _installed:
        # Зон не было и нет: сервер ведёт себя ровно как раньше.
        return
    await _reset()
    if not protected:
        # Последнюю зону удалили — правила сняты, дальше делать нечего.
        _installed = False
        return

    iface = config.WG_INTERFACE
    if not await _run("iptables", "-N", CHAIN):
        logger.warning("зоны: цепочка %s не создалась", CHAIN)
        return
    # Ответы на уже установленные соединения пропускаем без разбора:
    # иначе каждая зона требовала бы обратных правил, а ошибка в них
    # выглядит как «подключился, но ничего не открывается».
    await _run("iptables", "-A", CHAIN, "-m", "conntrack",
               "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")

    for client in clients:
        address = str(client.get("address") or "").split("/")[0]
        if not address:
            continue
        zone = zone_of(client, zones)
        allowed = list(zone.get("cidrs") or []) if zone else []
        for cidr in allowed:
            await _run("iptables", "-A", CHAIN, "-s", f"{address}/32",
                       "-d", cidr, "-j", "ACCEPT")
        # Всё остальное служебное — мимо, независимо от того, что клиент
        # прописал себе в конфиге.
        for cidr in protected:
            if cidr in allowed:
                continue
            await _run("iptables", "-A", CHAIN, "-s", f"{address}/32",
                       "-d", cidr, "-j", "DROP")
        if zone and not zone.get("internet"):
            # Зона без интернета: клиент видит только её подсети.
            await _run("iptables", "-A", CHAIN, "-s", f"{address}/32", "-j", "DROP")

    # Неизвестные адреса (клиент удалён, а сессия жива) в служебные сети
    # не пускаем вовсе.
    for cidr in protected:
        await _run("iptables", "-A", CHAIN, "-d", cidr, "-j", "DROP")

    if not await _run("iptables", "-I", "FORWARD", "1", "-i", iface, "-j", CHAIN):
        logger.warning("зоны: цепочка собрана, но не подключена к FORWARD")
        return
    _installed = True
    logger.info(
        "зоны: %d подсетей под охраной, клиентов с доступом %d",
        len(protected),
        sum(1 for c in clients if c.get("zone_id")),
    )
