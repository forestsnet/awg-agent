"""Пароль и сессия.

Пароль хранится bcrypt-хэшем в PASSWORD_HASH — тем же, что понимала
amnezia-wg-easy, чтобы переезд не требовал менять окружение. Без хэша
агент не стартует: панель управления сервером не должна открываться
кому угодно, кто нашёл порт.

Кука называется `connect.sid` намеренно. Так её ждут уже разошедшиеся
сборки бота: они искали в ответе строго это имя и молча ломались, когда
панель переименовала куку в `wg0.sid`. Имя ничего не стоит, а старые
боты продолжают работать без обновления.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

import bcrypt

from . import config

COOKIE_NAME = "connect.sid"


def verify_password(password: str) -> bool:
    if not config.PASSWORD_HASH or not isinstance(password, str):
        return False
    try:
        return bcrypt.checkpw(password.encode(), config.PASSWORD_HASH.encode())
    except (ValueError, TypeError):
        # Хэш битый — это наша ошибка установки, а не неверный пароль.
        # Логируем в вызывающем коде, сюда попадает просто «не подошёл».
        return False


def _sign(secret: str, payload: bytes) -> str:
    digest = hmac.new(secret.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def issue(secret: str, *, max_age: Optional[int] = None) -> str:
    body = json.dumps(
        {"exp": int(time.time()) + int(max_age or config.SESSION_MAX_AGE),
         "n": secrets.token_hex(8)},
        separators=(",", ":"),
    ).encode()
    raw = base64.urlsafe_b64encode(body).decode().rstrip("=")
    return f"{raw}.{_sign(secret, body)}"


def valid(secret: str, token: Optional[str]) -> bool:
    if not token or "." not in token:
        return False
    raw, _, signature = token.partition(".")
    try:
        body = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except Exception:  # noqa: BLE001
        return False
    if not hmac.compare_digest(_sign(secret, body), signature):
        return False
    try:
        return int(json.loads(body).get("exp", 0)) > time.time()
    except Exception:  # noqa: BLE001
        return False


def new_secret() -> str:
    return base64.b64encode(os.urandom(32)).decode()
