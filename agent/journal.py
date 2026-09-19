"""Журнал: кто, когда и откуда подключался.

«Последнее рукопожатие» отвечает на вопрос «сейчас он тут?» и ни на
какой другой. Для служебного доступа важнее другое: когда техник
заходил, сколько пробыл, с какого адреса и в какой зоне он при этом
был. Особенно когда речь про IPMI: разбор инцидента начинается с «кто
туда ходил на прошлой неделе».

Считаем по тем же данным, что уже собирает тик учёта трафика:
рукопожатие обновилось — значит, сессия живая. Пропало больше чем на
IDLE_GAP — сессия закрылась. Смена эндпоинта — новая сессия: человек
переехал в другую сеть.

Держим последние LIMIT записей: файл состояния читается целиком на
каждом старте, и журнал за год превратил бы его в мегабайты.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

# Сколько записей храним. Тысячи хватает на месяцы работы бастиона с
# десятком людей, а весит она сотни килобайт.
LIMIT = 1000
# Через сколько тишины считаем, что сессия закончилась. WireGuard
# обновляет рукопожатие примерно раз в две минуты, поэтому меньше
# пяти брать нельзя — насчитаем разрывов на ровном месте.
IDLE_GAP = timedelta(minutes=5)

KIND_CONNECTED = "connected"
KIND_DISCONNECTED = "disconnected"
KIND_ZONE = "zone"
KIND_CREATED = "created"
KIND_DELETED = "deleted"
KIND_ENABLED = "enabled"
KIND_DISABLED = "disabled"


def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat() + "Z"


def record(
    events: list[dict[str, Any]],
    kind: str,
    client: dict[str, Any] | None = None,
    *,
    at: Optional[datetime] = None,
    **extra: Any,
) -> dict[str, Any]:
    """Добавить запись и подрезать журнал."""
    entry: dict[str, Any] = {
        "at": _iso(at or datetime.utcnow()),
        "kind": kind,
    }
    if client:
        entry["client_id"] = client.get("id")
        entry["client"] = client.get("name")
        entry["address"] = client.get("address")
        if client.get("zone_id"):
            entry["zone_id"] = client.get("zone_id")
    entry.update({k: v for k, v in extra.items() if v is not None})
    events.append(entry)
    if len(events) > LIMIT:
        del events[: len(events) - LIMIT]
    return entry


def observe(
    events: list[dict[str, Any]],
    client: dict[str, Any],
    live: dict[str, Any],
    now: datetime,
) -> None:
    """Посмотреть на живые счётчики пира и дописать журнал.

    Состояние сессии держим в самом клиенте: `session` — начало,
    последнее рукопожатие, эндпоинт и счётчики на момент старта. Так
    после перезапуска агента незакрытая сессия закроется сама, а не
    повиснет навсегда.
    """
    handshake = live.get("latest_handshake_at")
    endpoint = live.get("endpoint") or None
    session = client.get("session") or None

    if handshake:
        rx = int(live.get("transfer_rx", 0))
        tx = int(live.get("transfer_tx", 0))
        if session and endpoint and session.get("endpoint") != endpoint:
            # Переехал в другую сеть: старую сессию закрываем, чтобы в
            # журнале было видно откуда и докуда он был.
            close(events, client, now, reason="сменил сеть")
            session = None
        if not session:
            client["session"] = {
                "started_at": _iso(now),
                "endpoint": endpoint,
                "rx0": rx,
                "tx0": tx,
                "last_at": _iso(now),
            }
            record(events, KIND_CONNECTED, client, at=now, endpoint=endpoint)
        else:
            session["last_at"] = _iso(now)
            if endpoint:
                session["endpoint"] = endpoint
        client["last_endpoint"] = endpoint or client.get("last_endpoint")
        return

    # Рукопожатий нет: либо человек ушёл, либо ещё не приходил.
    if session:
        last = parse(session.get("last_at"))
        if not last or now - last > IDLE_GAP:
            close(events, client, now)


def close(
    events: list[dict[str, Any]],
    client: dict[str, Any],
    now: datetime,
    *,
    reason: Optional[str] = None,
) -> None:
    """Закрыть сессию и записать, сколько она длилась и что прокачала."""
    session = client.pop("session", None)
    if not session:
        return
    started = parse(session.get("started_at"))
    last = parse(session.get("last_at")) or now
    rx = int(client.get("last_seen_rx") or 0) - int(session.get("rx0") or 0)
    tx = int(client.get("last_seen_tx") or 0) - int(session.get("tx0") or 0)
    record(
        events,
        KIND_DISCONNECTED,
        client,
        at=now,
        endpoint=session.get("endpoint"),
        # Длительность считаем до последнего рукопожатия, а не до
        # «сейчас»: иначе в каждую сессию добавлялись бы пять минут
        # ожидания, за которые мы решали, что человек ушёл.
        seconds=int((last - started).total_seconds()) if started else None,
        rx=max(rx, 0),
        tx=max(tx, 0),
        reason=reason,
    )


def parse(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).rstrip("Z"))
    except ValueError:
        return None


def select(
    events: list[dict[str, Any]],
    *,
    limit: int = 200,
    client_id: Optional[str] = None,
    kind: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Последние записи — свежие сверху."""
    rows = list(events)
    if client_id:
        rows = [e for e in rows if e.get("client_id") == client_id]
    if kind:
        rows = [e for e in rows if e.get("kind") == kind]
    return list(reversed(rows[-limit:]))
