"""Состояние: сервер, клиенты, запись на диск.

Всё держим в памяти и пишем на диск атомарно (файл рядом + rename):
оборванная запись не должна оставлять половину клиентов.

Отдельная забота — импорт из amnezia-wg-easy. Агент ставится на место
старой панели с тем же томом, и подмена контейнера не должна никого
отключить: при первом старте читаем её `wg0.json` и переносим клиентов
как есть, вместе с ключами и адресами.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from typing import Any, Optional

from . import awg, config, proto, render

logger = logging.getLogger("state")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


class Store:
    def __init__(self) -> None:
        self.server: dict[str, Any] = {}
        self.clients: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    # ── Загрузка ────────────────────────────────────────────────────

    async def load(self) -> None:
        os.makedirs(config.WG_PATH, exist_ok=True)
        if os.path.exists(config.STATE_PATH):
            with open(config.STATE_PATH, encoding="utf-8") as fh:
                data = json.load(fh)
            self.server = data.get("server") or {}
            self.clients = data.get("clients") or []
            logger.info("состояние загружено: клиентов %d", len(self.clients))
        elif os.path.exists(config.LEGACY_STATE_PATH):
            await self._import_legacy()
        if not self.server:
            await self._init_server()
            await self.persist()

    async def _init_server(self) -> None:
        private, public = await awg.keypair()
        self.server = {
            "private_key": private,
            "public_key": public,
            "params": proto.generate(
                config.AWG_PROTO,
                random_trailers=config.AWG_RANDOM_TRAILERS,
                disable_cookies=config.AWG_DISABLE_COOKIES,
            ),
            "i1": proto.signature_packet(),
            "created_at": _now(),
        }
        logger.info(
            "сервер инициализирован, протокол %s", self.server["params"]["proto"]
        )

    async def _import_legacy(self) -> None:
        """Перенос клиентов из amnezia-wg-easy.

        Ключи сервера и клиентов берём как есть — иначе у всех разом
        перестанут работать уже розданные конфиги. А вот параметры
        обфускации генерируем свои: у старой панели их набор
        заканчивается на 2.0, ключа заголовков там нет вовсе.
        """
        with open(config.LEGACY_STATE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        legacy_server = data.get("server") or {}
        await self._init_server()
        if legacy_server.get("privateKey"):
            self.server["private_key"] = legacy_server["privateKey"]
            self.server["public_key"] = legacy_server.get("publicKey") or (
                await awg.pubkey(legacy_server["privateKey"])
            )

        for cid, item in (data.get("clients") or {}).items():
            self.clients.append({
                "id": cid,
                "name": item.get("name") or cid[:8],
                "enabled": bool(item.get("enabled", True)),
                "address": item.get("address"),
                "private_key": item.get("privateKey"),
                "public_key": item.get("publicKey"),
                "preshared_key": item.get("preSharedKey"),
                "i1": proto.signature_packet(),
                "created_at": item.get("createdAt") or _now(),
                "updated_at": _now(),
            })
        logger.info(
            "импорт из amnezia-wg-easy: перенесено клиентов %d", len(self.clients)
        )
        await self.persist()

    # ── Запись ──────────────────────────────────────────────────────

    async def persist(self) -> None:
        payload = json.dumps(
            {"server": self.server, "clients": self.clients},
            ensure_ascii=False,
            indent=1,
        )
        tmp = config.STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, config.STATE_PATH)

        conf = render.server_conf(self.server, self.clients)
        tmp_conf = config.CONF_PATH + ".tmp"
        with open(tmp_conf, "w", encoding="utf-8") as fh:
            fh.write(conf)
        os.chmod(tmp_conf, 0o600)
        os.replace(tmp_conf, config.CONF_PATH)

    async def apply(self) -> None:
        """Записать состояние и накатить его на живой интерфейс."""
        await self.persist()
        await awg.sync()

    # ── Клиенты ─────────────────────────────────────────────────────

    def find(self, key: str) -> Optional[dict[str, Any]]:
        """Клиент по id или по имени.

        Бот местами ходит по id, местами по имени — и это не его вина:
        у одной ручки в старой панели параметр назывался clientId, у
        другой тем же значением подставлялось имя. Принимаем оба.
        """
        for client in self.clients:
            if client.get("id") == key:
                return client
        for client in self.clients:
            if client.get("name") == key:
                return client
        return None

    async def create(self, name: str) -> dict[str, Any]:
        async with self._lock:
            private, public = await awg.keypair()
            client = {
                "id": str(uuid.uuid4()),
                "name": name,
                "enabled": True,
                "address": render.next_address({c["address"] for c in self.clients}),
                "private_key": private,
                "public_key": public,
                "preshared_key": await awg.genpsk(),
                # Свой сигнатурный пакет каждому: одинаковый I1 у всех и
                # есть та примета, по которой их вычисляют.
                "i1": proto.signature_packet(),
                "created_at": _now(),
                "updated_at": _now(),
            }
            self.clients.append(client)
            await self.apply()
            return client

    async def delete(self, key: str) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            self.clients.remove(client)
            await self.apply()
            return True

    async def set_enabled(self, key: str, enabled: bool) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            client["enabled"] = enabled
            client["updated_at"] = _now()
            await self.apply()
            return True

    async def rename(self, key: str, name: str) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            client["name"] = name
            client["updated_at"] = _now()
            await self.apply()
            return True


store = Store()
