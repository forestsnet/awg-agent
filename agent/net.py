"""Через какой интерфейс агент выпускает трафик наружу.

Установщик работает на хосте и видит хостовое имя интерфейса — ens3,
enp1s0, что там у провайдера. Агент же живёт в контейнере, где наружу
ведёт свой eth0. MASQUERADE с чужим `-o` не совпадает ни с одним
пакетом и при этом не ошибается: интерфейс поднимается, хендшейк
проходит, клиент показывает «подключено» — и на этом всё. Самый
неприятный вид поломки, поэтому имя из окружения берём только если
такой интерфейс здесь действительно есть, иначе спрашиваем маршруты.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from . import config

logger = logging.getLogger(__name__)

ROUTE_TABLE = "/proc/net/route"

_cached: Optional[str] = None


def _present(name: str) -> bool:
    return bool(name) and os.path.isdir(f"/sys/class/net/{name}")


def default_route_device(path: str = ROUTE_TABLE) -> Optional[str]:
    """Интерфейс маршрута по умолчанию.

    Читаем /proc, а не зовём `ip route`: это чтение файла вместо запуска
    процесса, и работает даже там, где iproute2 не положили.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            rows = fh.read().splitlines()[1:]
    except OSError:
        return None
    for row in rows:
        parts = row.split()
        # Iface Destination Gateway Flags RefCnt Use Metric Mask …
        # Маршрут по умолчанию — нулевые и адрес назначения, и маска.
        if len(parts) > 7 and parts[1] == "00000000" and parts[7] == "00000000":
            return parts[0]
    return None


def egress_device() -> str:
    """Имя интерфейса, на который вешается NAT."""
    global _cached
    if _cached:
        return _cached
    wanted = (config.WG_DEVICE or "").strip()
    if _present(wanted):
        _cached = wanted
        return _cached
    # Маршруты не прочитались — в контейнере такого не бывает, но если
    # уж случилось, докеровское имя ближе к истине, чем интерфейс хоста,
    # которого здесь заведомо нет.
    found = default_route_device() or "eth0"
    if wanted and wanted != found:
        logger.warning(
            "интерфейса %s здесь нет — NAT вешаем на %s", wanted, found
        )
    _cached = found
    return _cached


IF_INET6 = "/proc/net/if_inet6"


def has_global_ipv6(path: str = IF_INET6) -> bool:
    """Есть ли у машины глобальный IPv6.

    От ответа зависит, что делать с v6-трафиком клиентов: выпускать его
    наружу через NAT66 или оставить умирать в туннеле. Смотрим /proc, а
    не `ip -6 addr`: это чтение файла, и работает без iproute2.

    Формат строки: адрес, индекс, длина префикса, scope, флаги, имя.
    Нас интересует scope 00 (global) на любом интерфейсе, кроме
    петлевого: адрес на eth0 или на бридже — одинаково рабочий.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            rows = fh.read().splitlines()
    except OSError:
        return False
    for row in rows:
        parts = row.split()
        if len(parts) < 6:
            continue
        addr, scope, name = parts[0], parts[3], parts[5]
        if name == "lo" or scope != "00":
            continue
        # fe80::/10 — канальные, fc00::/7 — приватные ULA: наружу с ними
        # не выйти, даже если ядро назвало их глобальными.
        head = addr[:4].lower()
        if head.startswith("fe8") or head.startswith("fc") or head.startswith("fd"):
            continue
        return True
    return False


def reset_cache() -> None:
    """Сбросить запомненный интерфейс (нужно тестам)."""
    global _cached
    _cached = None
