"""Персональные логи пользователей (опционально, по галочке на клиенте).

По файлу на клиента, JSONL: сессии (из journal), торрент-хиты и
периодические срезы трафика — без капа journal (1000) и не раздувая
state.json. Ротация в процессе, по размеру: агент живёт в контейнере,
host-logrotate ему недоступен — тот же принцип, что и у btguard (не
зависим ни от journald, ни от ротации хоста).

Файлы: `<WG_PATH>/user-logs/<client_id>.log` (активный) и сжатые
поколения `<client_id>.log.1.gz` … `.KEEP.gz`. Жмём сразу — при
дозаписи в отдельный файл delaycompress не нужен.
"""
from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
from datetime import datetime
from typing import Any

from . import config

logger = logging.getLogger("userlog")


def _base() -> str:
    return os.path.join(config.WG_PATH, "user-logs")


def _path(client_id: str) -> str:
    return os.path.join(_base(), f"{client_id}.log")


def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def enabled(client: dict[str, Any]) -> bool:
    return bool(client.get("log_enabled"))


def _rotate(p: str) -> None:
    """Сдвиг поколений и сжатие активного файла в .1.gz."""
    keep = max(1, int(config.USERLOG_KEEP))
    oldest = f"{p}.{keep}.gz"
    if os.path.exists(oldest):
        os.remove(oldest)
    for i in range(keep - 1, 0, -1):
        src = f"{p}.{i}.gz"
        if os.path.exists(src):
            os.replace(src, f"{p}.{i + 1}.gz")
    if os.path.exists(p):
        with open(p, "rb") as fi, gzip.open(f"{p}.1.gz", "wb") as fo:
            shutil.copyfileobj(fi, fo)
        os.remove(p)


def write(client: dict[str, Any], entry: dict[str, Any]) -> None:
    """Дописать запись в лог клиента (если у него включена галочка)."""
    if not enabled(client):
        return
    cid = client.get("id")
    if not cid:
        return
    rec = {"at": entry.get("at") or _now(), **entry}
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    try:
        os.makedirs(_base(), exist_ok=True)
        p = _path(cid)
        if os.path.exists(p) and os.path.getsize(p) + len(line.encode()) > int(config.USERLOG_MAX_BYTES):
            _rotate(p)
        with open(p, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        logger.exception("userlog: не записал для %s", cid)


def tail(client_id: str, limit: int = 200) -> list[dict[str, Any]]:
    """Последние N записей активного файла, свежие сверху."""
    p = _path(client_id)
    rows: list[dict[str, Any]] = []
    try:
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                for ln in f.readlines()[-limit:]:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        rows.append(json.loads(ln))
                    except ValueError:
                        rows.append({"raw": ln})
    except OSError:
        logger.exception("userlog: не прочитал %s", client_id)
    return list(reversed(rows))


def size(client_id: str) -> int:
    """Суммарный размер логов клиента (активный + все поколения), байт."""
    base = _base()
    total = 0
    try:
        for fn in os.listdir(base):
            if fn == f"{client_id}.log" or fn.startswith(f"{client_id}.log."):
                try:
                    total += os.path.getsize(os.path.join(base, fn))
                except OSError:
                    pass
    except OSError:
        pass
    return total


def purge(client_id: str) -> None:
    """Удалить все логи клиента (активный + поколения)."""
    base = _base()
    try:
        names = os.listdir(base)
    except OSError:
        return
    for fn in names:
        if fn == f"{client_id}.log" or fn.startswith(f"{client_id}.log."):
            try:
                os.remove(os.path.join(base, fn))
            except OSError:
                pass
