"""Параметры обфускации AmneziaWG.

Логика повторяет наш awgcfg.py — установка через агент и нативная
установка должны давать конфиги одного качества.

Главное правило: значения генерируются НА УСТАНОВКУ, а не берутся из
констант. Установщики, разносившие один и тот же I1 и одинаковые H1..H4
по всем серверам, ровно этим и выдавали своих пользователей: одна
заблокированная сигнатура накрывала всех разом.

Что обязано совпадать у сервера и клиента: Jc/Jmin/Jmax, S1..S4,
H1..H4, HeaderProtectionKey. Сигнатурные пакеты I1..I5 совпадений не
требуют — их шлёт инициатор, принимающая сторона просто отбрасывает,
поэтому каждому клиенту генерируем свой.
"""
from __future__ import annotations

import base64
import os
import random
import secrets
from typing import Any

# Домены для DNS-подобной сигнатуры: трафик к ним никого не удивляет, а
# список нужен затем, чтобы у каждого конфига имя было своё.
_SIG_DOMAINS = (
    "dns.icloud.com", "cdn.cloudflare.net", "api.gstatic.com",
    "static.licdn.com", "edge.microsoft.com", "assets.msn.com",
    "ocsp.digicert.com", "clients.google.com", "cdn.jsdelivr.net",
    "telemetry.mozilla.org",
)


def _dns_name_hex(name: str) -> str:
    """Доменное имя в DNS-формате: длина метки, метка, ..., 0x00."""
    parts = []
    for label in name.split("."):
        parts.append("%02x" % len(label))
        parts.append(label.encode("ascii").hex())
    parts.append("00")
    return "".join(parts)


def signature_packet() -> str:
    """Сигнатурный пакет (I1..I5) на языке CPS — свой для каждого конфига.

    Перед хендшейком уходит датаграмма, похожая на обычный DNS-запрос
    или QUIC Initial: фильтру проще пропустить знакомый протокол, чем
    разбирать непонятный шум.
    """
    if random.random() < 0.7:
        # DNS-запрос с EDNS0-падингом. Случайные байты кладём не хвостом
        # после пакета (так настоящий резолвер не делает), а в опцию
        # padding — она для этого и придумана.
        txid = "%04x" % random.randint(0, 0xFFFF)
        head = txid + "0100" + "0001" + "0000" + "0000" + "0001"
        question = _dns_name_hex(random.choice(_SIG_DOMAINS)) + "00010001"
        pad = random.randint(16, 48)
        opt = "00" + "0029" + "04d0" + "00000000"
        opt += "%04x" % (pad + 4) + "000c" + "%04x" % pad
        return "<b 0x%s%s%s><r %d>" % (head, question, opt, pad)

    # QUIC Initial: длинный заголовок, версия 1, случайные connection id.
    ver = "c3" + "00000001"
    return (
        "<b 0x%s08><r 8><b 0x08><r 8><b 0x0045%02x><t><r %d>"
        % (ver, random.randint(0x10, 0xFF), random.randint(8, 24))
    )


def header_protection_key() -> str:
    """Ключ шифрования заголовков: 32 байта в base64, как обычный ключ WG."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


def generate(proto: int, *, random_trailers: bool, disable_cookies: bool) -> dict[str, Any]:
    """Набор параметров на одну установку.

    proto=3 добавляет к набору 2.0 ключ заголовков и тумблеры 3.1.
    """
    # У 3.0 первые 12 байт каждого padding'а работают как nonce для
    # шифрования заголовков — меньше 12 протокол защиту просто не включит.
    s_min = 12 if proto >= 3 else 3
    s1 = secrets.randbelow(128 - s_min) + s_min
    s2 = secrets.randbelow(128 - s_min) + s_min
    # S2 не должен совпасть с S1+56: иначе handshake-пакеты становятся
    # неразличимы по длине и обфускация теряет смысл.
    while s2 == s1 + 56:
        s2 = secrets.randbelow(128 - s_min) + s_min

    headers: list[int] = []
    while len(headers) < 4:
        value = secrets.randbelow(0x7FFFFF00 - 0x10000011) + 0x10000011
        if value not in headers:
            headers.append(value)

    params: dict[str, Any] = {
        "proto": 3 if proto >= 3 else 2,
        "jc": secrets.randbelow(8) + 3,
        "jmin": 50,
        "jmax": 1000,
        "s1": s1,
        "s2": s2,
        "s3": secrets.randbelow(128 - s_min) + s_min,
        "s4": secrets.randbelow(128 - s_min) + s_min,
        "h1": headers[0],
        "h2": headers[1],
        "h3": headers[2],
        "h4": headers[3],
    }
    if proto >= 3:
        params["header_protection_key"] = header_protection_key()
        params["random_trailers"] = bool(random_trailers)
        params["disable_cookies"] = bool(disable_cookies)
    return params


def interface_lines(params: dict[str, Any]) -> list[str]:
    """Строки обфускации для секции [Interface].

    Порядок фиксированный: так конфиги разных версий агента можно
    сравнивать глазами и диффом.
    """
    lines = [
        f"Jc = {params['jc']}",
        f"Jmin = {params['jmin']}",
        f"Jmax = {params['jmax']}",
        f"S1 = {params['s1']}",
        f"S2 = {params['s2']}",
    ]
    if int(params.get("proto", 2)) >= 3:
        lines += [f"S3 = {params['s3']}", f"S4 = {params['s4']}"]
    lines += [
        f"H1 = {params['h1']}",
        f"H2 = {params['h2']}",
        f"H3 = {params['h3']}",
        f"H4 = {params['h4']}",
    ]
    if int(params.get("proto", 2)) >= 3:
        if params.get("header_protection_key"):
            lines.append(f"HeaderProtectionKey = {params['header_protection_key']}")
        if params.get("random_trailers"):
            lines.append("RandomTrailers = on")
        if params.get("disable_cookies"):
            lines.append("DisableCookies = on")
    return lines
