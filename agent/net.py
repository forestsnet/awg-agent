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


def reset_cache() -> None:
    """Сбросить запомненный интерфейс (нужно тестам)."""
    global _cached
    _cached = None
