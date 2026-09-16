"""Лимиты трафика и срок действия.

Считать приходится самим: `awg show dump` отдаёт счётчики пира с
момента, как он появился в интерфейсе. Рестарт контейнера, переустановка
или простое выключение-включение клиента обнуляют их — если брать эти
числа как есть, лимит сбрасывался бы сам собой.

Поэтому агент копит дельты: каждый тик берёт текущее значение, прибавляет
разницу с прошлым замером и складывает в своё поле, которое лежит в
clients.json и переживает всё перечисленное.
"""
from __future__ import annotations

import calendar
import logging
from datetime import datetime, timedelta
from typing import Any, Optional

logger = logging.getLogger("quota")

PERIODS = ("none", "day", "week", "month", "year")

# Почему клиент выключен. Ручное выключение лимиты не трогают: админ
# выключил — значит выключено, до его же решения.
MANUAL = "manual"
QUOTA = "quota"
EXPIRED = "expired"


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def period_end(start: datetime, period: str) -> Optional[datetime]:
    """Когда закончится текущий период.

    Месяц и год считаем по календарю, а не в сутках: «раз в месяц» для
    человека — это то же число следующего месяца, а не 30 дней.
    """
    if period == "day":
        return start + timedelta(days=1)
    if period == "week":
        return start + timedelta(days=7)
    if period == "month":
        year, month = (start.year + 1, 1) if start.month == 12 else (start.year, start.month + 1)
        day = min(start.day, calendar.monthrange(year, month)[1])
        return start.replace(year=year, month=month, day=day)
    if period == "year":
        # 29 февраля в невисокосном году — 28-е, иначе ValueError.
        day = min(start.day, calendar.monthrange(start.year + 1, start.month)[1])
        return start.replace(year=start.year + 1, day=day)
    return None


def delta(previous: int, current: int) -> int:
    """Прирост трафика между замерами.

    Счётчик меньше прошлого — значит пир перезаводили (рестарт
    интерфейса, включение после выключения). Тогда весь текущий и есть
    прирост, а не отрицательная разница.
    """
    if current < 0:
        return 0
    return current - previous if current >= previous else current


def apply(client: dict[str, Any], now: datetime) -> list[str]:
    """Пересчитать период, лимит и срок. Возвращает список событий.

    Чистая функция над словарём клиента: её можно гонять тестом без
    интерфейса, базы и таймеров.
    """
    events: list[str] = []
    period = str(client.get("quota_period") or "none")

    # 1. Сброс по расписанию.
    if period != "none":
        started = parse_iso(client.get("quota_started_at")) or now
        end = period_end(started, period)
        while end and now >= end:
            client["quota_used"] = 0
            client["quota_started_at"] = iso(end)
            started, end = end, period_end(end, period)
            events.append("quota_reset")
        if not client.get("quota_started_at"):
            client["quota_started_at"] = iso(now)

    # 2. Срок действия. Он сильнее лимита: истёк — включать нечего.
    expires = parse_iso(client.get("expires_at"))
    if expires and now >= expires:
        if client.get("enabled", True):
            client["enabled"] = False
            client["disabled_reason"] = EXPIRED
            events.append("expired")
        return events

    limit = int(client.get("quota_bytes") or 0)
    used = int(client.get("quota_used") or 0)

    # 3. Лимит выбран — выключаем.
    if limit and used >= limit:
        if client.get("enabled", True):
            client["enabled"] = False
            client["disabled_reason"] = QUOTA
            events.append("quota_exceeded")
        return events

    # 4. Сам выключился по лимиту или сроку, а причина отпала — вернуть.
    if not client.get("enabled", True) and client.get("disabled_reason") in (QUOTA, EXPIRED):
        client["enabled"] = True
        client["disabled_reason"] = None
        events.append("restored")
    return events
