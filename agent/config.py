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
# Подсеть клиентов целиком. Нужна ради тех, кому мало 253 адресов:
# /16 даёт 65 тысяч, и второй агент ради этого поднимать не приходится.
# Пусто — берём /24 вокруг WG_DEFAULT_ADDRESS, как было.
WG_SUBNET = os.environ.get("WG_SUBNET", "").strip()
WG_DEFAULT_DNS = os.environ.get("WG_DEFAULT_DNS", "1.1.1.1")
WG_ALLOWED_IPS = os.environ.get("WG_ALLOWED_IPS", "0.0.0.0/0, ::/0")

# IPv6 внутри туннеля.
#
# Без него получается ловушка: клиенту в AllowedIPs пишут ::/0, а адреса
# IPv6 у интерфейса нет. iOS и Android поднимают маршрут для v6 только
# когда у туннеля есть v6-адрес — значит весь IPv6-трафик идёт мимо VPN,
# напрямую от оператора. Клиент при этом видит «подключено», а половина
# трафика (и его настоящий адрес) наружу. Заодно мимо проходят все
# лимиты: скорость и квоту мы считаем по туннелю.
#
# Поэтому туннелю всегда выдаём ULA-подсеть: есть у хоста глобальный
# IPv6 — клиенты получают рабочий v6 через NAT66; нет — v6 упирается в
# сервер и приложение за четверть секунды откатывается на v4. Наружу
# мимо VPN не уходит ничего.
WG_IPV6 = _flag("WG_IPV6", True)
# Пусто — считаем ULA из v4-подсети (детерминированно, без коллизий
# между экземплярами на одной машине).
WG_SUBNET6 = os.environ.get("WG_SUBNET6", "").strip()
WG_PERSISTENT_KEEPALIVE = _int("WG_PERSISTENT_KEEPALIVE", 25)

# ── Протокол ────────────────────────────────────────────────────────
# `awg` — AmneziaWG с обфускацией, `wg` — обычный WireGuard. Отличий по
# сути два: набор строк в конфиге и имя утилиты. Держать ради этого два
# агента незачем, тем более что оба бинарника лежат в одном образе.
VPN_PROTO = (os.environ.get("VPN_PROTO", "awg") or "awg").strip().lower()
IS_AWG = VPN_PROTO != "wg"
# Имена утилит и качдиска подставляются отсюда, чтобы остальной код не
# знал, в каком мы режиме.
BIN = "awg" if IS_AWG else "wg"
BIN_QUICK = "awg-quick" if IS_AWG else "wg-quick"

# Сколько данных влезает в пакет.
#
# Замер по счётчикам туннеля: обычный WireGuard добавляет к пакету 72
# байта (заголовок, тег и IP/UDP), AmneziaWG 3.1 — 131, потому что
# поверх лежат защита заголовков и случайные хвосты. При пути в 1500
# это потолки 1428 и 1369 — и наблюдаемый обрыв у awg между 1360 и 1380
# ровно там, где расчётный.
#
# Отсюда дефолты: у wg общепринятые 1420 (влезает с запасом в 8 байт),
# у awg 1280, как у клиента AmneziaVPN — запаса хватает и на PPPoE, и
# на вложенные туннели, а скорость на таком MTU не отличается. Выше
# потолка поломка выглядит как исправная: хендшейк проходит, мелкие
# пакеты ходят, крупные пропадают целиком.
WG_MTU = os.environ.get("WG_MTU", "").strip() or ("1280" if IS_AWG else "1420")

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


# ── Торрент-блокировщик (btguard) ───────────────────────────────────
# Значения — стартовые сиды. Дальше конфиг живёт в состоянии и правится по API/в панели.
TORRENT_ENABLED = _flag("TORRENT_ENABLED", True)
TORRENT_WEBHOOK_URL = os.environ.get("TORRENT_WEBHOOK_URL", "").strip()
TORRENT_WEBHOOK_SECRET = os.environ.get("TORRENT_WEBHOOK_SECRET", "").strip()
TORRENT_NODE_NAME = os.environ.get("TORRENT_NODE_NAME", "").strip()
TORRENT_BLOCK_DURATION = _int("TORRENT_BLOCK_DURATION", 3600)

# Персональные логи пользователей (опционально, по галочке на клиенте).
# Ротация в процессе, по размеру — агент в контейнере, host-logrotate нет.
USERLOG_MAX_BYTES = _int("USERLOG_MAX_BYTES", 5 * 1024 * 1024)
USERLOG_KEEP = _int("USERLOG_KEEP", 5)
USERLOG_SNAPSHOT_SECONDS = _int("USERLOG_SNAPSHOT_SECONDS", 900)
