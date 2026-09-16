"""Настройки агента.

Имена переменных намеренно совпадают с amnezia-wg-easy: агент ставится
на место старой панели тем же compose-файлом, и существующие установки
переезжают без правки окружения.
"""
from __future__ import annotations

import os


def _int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name, "")).strip() or default)
    except ValueError:
        return default


def _flag(name: str, default: bool = False) -> bool:
    raw = str(os.environ.get(name, "")).strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


# ── Сеть и веб ──────────────────────────────────────────────────────
PORT = _int("PORT", 51821)
WEBUI_HOST = os.environ.get("WEBUI_HOST", "0.0.0.0")
PASSWORD_HASH = os.environ.get("PASSWORD_HASH", "").strip()

# ── WireGuard ───────────────────────────────────────────────────────
WG_INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
WG_PATH = os.environ.get("WG_PATH", "/etc/amnezia/amneziawg")
WG_HOST = os.environ.get("WG_HOST", "").strip()
WG_PORT = _int("WG_PORT", 51820)
# Порт, который попадёт в конфиг клиента. Отличается от WG_PORT, когда
# наружу проброшен другой порт (NAT, docker -p 443:51820).
WG_CONFIG_PORT = _int("WG_CONFIG_PORT", WG_PORT)
WG_DEVICE = os.environ.get("WG_DEVICE", "eth0")
WG_DEFAULT_ADDRESS = os.environ.get("WG_DEFAULT_ADDRESS", "10.8.0.x")
WG_DEFAULT_DNS = os.environ.get("WG_DEFAULT_DNS", "1.1.1.1")
WG_ALLOWED_IPS = os.environ.get("WG_ALLOWED_IPS", "0.0.0.0/0, ::/0")
WG_PERSISTENT_KEEPALIVE = _int("WG_PERSISTENT_KEEPALIVE", 25)
WG_MTU = os.environ.get("WG_MTU", "").strip()

# ── AmneziaWG ───────────────────────────────────────────────────────
# Поколение протокола для НОВОЙ установки:
#   2 — Jc/Jmin/Jmax, S1..S4, H1..H4, сигнатуры I1..I5;
#   3 — плюс HeaderProtectionKey (3.0) и RandomTrailers/DisableCookies (3.1).
# Клиент старее 3.0 к серверу с HeaderProtectionKey не подключится
# вовсе: заголовки шифрованы, пакеты молча отбрасываются. Поэтому
# поколение выбирается осознанно, а не «по максимуму».
AWG_PROTO = _int("AWG_PROTO", 3)
AWG_RANDOM_TRAILERS = _flag("AWG_RANDOM_TRAILERS", True)
AWG_DISABLE_COOKIES = _flag("AWG_DISABLE_COOKIES", False)

# ── Поведение агента ────────────────────────────────────────────────
# Насколько долго держим разобранный `awg show dump`. Список клиентов
# открывают часто, а трафик за секунду не меняется настолько, чтобы
# ради него дёргать бинарник на каждый запрос.
STATS_TTL_SECONDS = float(os.environ.get("STATS_TTL_SECONDS", "1") or 1)
SESSION_MAX_AGE = _int("SESSION_MAX_AGE", 60 * 60 * 24)
# Как часто пересчитываем трафик, лимиты и сроки. Реже — дешевле, но
# клиент успеет прокачать больше сверх лимита, прежде чем его выключат.
QUOTA_TICK_SECONDS = _int("QUOTA_TICK_SECONDS", 10)
# Сколько дней держим историю расхода. 90 строк на клиента — это
# десятки килобайт на весь файл состояния, зато видно сезонность.
HISTORY_DAYS = _int("HISTORY_DAYS", 90)
# Рубильник шейпера. Если tc на ядре хоста недоступен (бывает на старых
# OpenVZ-подобных), лучше выключить, чем ловить ошибки каждый раз.
SHAPER_ENABLED = _flag("SHAPER_ENABLED", True)
# Поднимать ли интерфейс при старте. Выключается, когда агент запускают
# рядом с уже поднятым awg (отладка, миграция).
WG_AUTO_UP = _flag("WG_AUTO_UP", True)

CONF_PATH = os.path.join(WG_PATH, f"{WG_INTERFACE}.conf")
STATE_PATH = os.path.join(WG_PATH, "clients.json")
# Файл состояния amnezia-wg-easy: из него импортируем клиентов при
# первом старте, чтобы подмена контейнера никого не отключила.
LEGACY_STATE_PATH = os.path.join(WG_PATH, f"{WG_INTERFACE}.json")
