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
from datetime import datetime
from typing import Any, Optional

from . import awg, config, journal, proto, quota, render, shaper, upstream, zones

logger = logging.getLogger("state")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())


def _prune_history(client: dict[str, Any]) -> None:
    """Держим историю в пределах HISTORY_DAYS, считая по датам.

    Не по количеству записей: дни простоя в историю не попадают, и по
    счёту записей «последние 90» могли бы растянуться на годы.
    """
    history = client.get("history") or {}
    if len(history) <= config.HISTORY_DAYS:
        return
    for date in sorted(history)[: len(history) - config.HISTORY_DAYS]:
        history.pop(date, None)


class Store:
    def __init__(self) -> None:
        self.server: dict[str, Any] = {}
        self.clients: list[dict[str, Any]] = []
        # Бастион: зоны доступа и туннели до чужих сетей. Пустые списки
        # — обычный VPN-сервер, который ведёт себя как раньше.
        self.zones: list[dict[str, Any]] = []
        self.upstreams: list[dict[str, Any]] = []
        # Журнал подключений: кто, когда и откуда. «Последнее
        # рукопожатие» отвечает только на «сейчас он тут?», а для
        # служебного доступа нужна история.
        self.events: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    # ── Загрузка ────────────────────────────────────────────────────

    async def load(self) -> None:
        os.makedirs(config.WG_PATH, exist_ok=True)
        if os.path.exists(config.STATE_PATH):
            with open(config.STATE_PATH, encoding="utf-8") as fh:
                data = json.load(fh)
            self.server = data.get("server") or {}
            self.clients = data.get("clients") or []
            self.zones = data.get("zones") or []
            self.upstreams = data.get("upstreams") or []
            self.events = data.get("events") or []
            logger.info("состояние загружено: клиентов %d", len(self.clients))
        elif os.path.exists(config.LEGACY_STATE_PATH):
            await self._import_legacy()
        if not self.server:
            await self._init_server()
        # Конфиг интерфейса пересобираем на каждом старте. Он собран из
        # состояния и окружения, а они между запусками меняются: агент
        # переехал в новый контейнер — сменился интерфейс для NAT,
        # обновился образ — поменялись правила. PostUp отрабатывает
        # ровно один раз, при подъёме интерфейса, и если на диске лежит
        # конфиг позапрошлой версии, чинить его потом уже некому.
        await self.persist()

    async def _init_server(self) -> None:
        private, public = await awg.keypair()
        params = (
            proto.generate(
                config.AWG_PROTO,
                random_trailers=config.AWG_RANDOM_TRAILERS,
                disable_cookies=config.AWG_DISABLE_COOKIES,
            )
            if config.IS_AWG
            else {"proto": 0}
        )
        self.server = {
            "private_key": private,
            "public_key": public,
            "params": params,
            "i1": proto.signature_packet() if config.IS_AWG else None,
            "created_at": _now(),
        }
        logger.info(
            "сервер инициализирован: %s, протокол %s",
            config.VPN_PROTO, params.get("proto"),
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
                # Лимитов у старой панели не было — заводим пустые.
                "quota_bytes": 0,
                "quota_period": "none",
                "quota_used": 0,
                "quota_started_at": _now(),
                "traffic_total": 0,
                "expires_at": None,
                "disabled_reason": None,
                "rate_bps": 0,
                "history": {},
                "last_seen_rx": 0,
                "last_seen_tx": 0,
            })
        logger.info(
            "импорт из amnezia-wg-easy: перенесено клиентов %d", len(self.clients)
        )
        await self.persist()

    # ── Запись ──────────────────────────────────────────────────────

    async def persist_state(self) -> None:
        """Только clients.json — конфиг интерфейса не трогаем."""
        payload = json.dumps(
            {
                "server": self.server,
                "clients": self.clients,
                "zones": self.zones,
                "upstreams": self.upstreams,
                "events": self.events,
            },
            ensure_ascii=False,
            indent=1,
        )
        tmp = config.STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, config.STATE_PATH)

    async def persist(self) -> None:
        await self.persist_state()
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
        await self.reapply()

    async def reapply(self) -> None:
        """Накатить правила на живое ядро, не трогая файлы на диске.

        Отдельно от apply(), потому что это нужно ещё и на старте:
        шейпер, апстримы и зоны живут в ядре и исчезают вместе с
        контейнером. Раньше их перестраивало только изменение клиента —
        после перезапуска агента лимиты и зоны молча переставали
        действовать, а туннели провайдеров оставались опущенными.
        """
        # Шейпер после синка: правила вешаются на адреса клиентов, а их
        # состав только что мог измениться.
        try:
            await shaper.apply(self.clients)
        except Exception:  # noqa: BLE001
            logger.exception("шейпер не применился")
        # Апстримы раньше зон: зона без поднятого туннеля — это закрытый
        # доступ, а не открытый, так что порядок безопасен в любом случае.
        try:
            await upstream.apply(self.upstreams)
        except Exception:  # noqa: BLE001
            logger.exception("апстримы не применились")
        try:
            await zones.apply(self.clients, self.zones, self.upstreams)
        except Exception:  # noqa: BLE001
            logger.exception("зоны не применились")

    # ── Резервная копия ─────────────────────────────────────────────

    def export_state(self) -> dict[str, Any]:
        """Всё, чего нет больше нигде: ключи сервера и клиентов.

        Конфиги и правила из этого собираются заново, а вот приватные
        ключи существуют ровно в одном экземпляре — на этой машине. Если
        VPS умер, без копии клиентам придётся раздавать новые конфиги.

        Секрет сессий намеренно не отдаём: он к восстановлению отношения
        не имеет, а лишний секрет в архиве — лишний секрет в архиве.
        """
        server = {k: v for k, v in self.server.items() if k != "session_secret"}
        return {
            "version": 1,
            "vpn": config.VPN_PROTO,
            "interface": config.WG_INTERFACE,
            "subnet": str(render.subnet()),
            "created_at": _now(),
            "server": server,
            "clients": self.clients,
        }

    async def import_state(self, data: dict[str, Any]) -> int:
        """Заменить состояние присланным. Возвращает число клиентов.

        Проверяем совместимость до того, как что-то трогать: копия от
        AmneziaWG на обычном WireGuard даст конфиг с параметрами, на
        которых wg-quick падает, а копия из другой подсети — адреса, до
        которых с этого интерфейса не достучаться. Обе поломки чинятся
        только руками по SSH, ради чего всё и затевалось.
        """
        if not isinstance(data, dict):
            raise ValueError("Не похоже на резервную копию")
        server = data.get("server")
        clients = data.get("clients")
        if not isinstance(server, dict) or not server.get("private_key"):
            raise ValueError("В копии нет ключа сервера")
        if not isinstance(clients, list):
            raise ValueError("В копии нет списка клиентов")
        vpn = str(data.get("vpn") or config.VPN_PROTO)
        if vpn != config.VPN_PROTO:
            raise ValueError(
                f"Копия снята с {vpn}, а здесь {config.VPN_PROTO} — "
                "поднимите агент в том же режиме"
            )
        subnet = str(data.get("subnet") or "")
        current = str(render.subnet())
        if subnet and subnet != current:
            raise ValueError(
                f"Копия из подсети {subnet}, а здесь {current} — "
                "задайте WG_SUBNET и перезапустите агент"
            )

        async with self._lock:
            # Свой секрет сессий оставляем: иначе восстановление выкинет
            # из панели того, кто его и запустил.
            secret = self.server.get("session_secret")
            self.server = dict(server)
            if secret:
                self.server["session_secret"] = secret
            self.clients = [dict(c) for c in clients]
            await self.apply()
        logger.info("состояние восстановлено из копии: клиентов %d", len(self.clients))
        return len(self.clients)

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
                "i1": proto.signature_packet() if config.IS_AWG else None,
                "created_at": _now(),
                "updated_at": _now(),
                # Лимиты: 0 — без лимита, период сброса «none».
                "quota_bytes": 0,
                "quota_period": "none",
                "quota_used": 0,
                "quota_started_at": _now(),
                "traffic_total": 0,
                "expires_at": None,
                "disabled_reason": None,
                # 0 — скорость не ограничена.
                "rate_bps": 0,
                # Расход по дням: {"2026-09-16": {"rx": …, "tx": …}}.
                "history": {},
                # Последние сырые счётчики пира: по ним считаем прирост.
                "last_seen_rx": 0,
                "last_seen_tx": 0,
            }
            self.clients.append(client)
            journal.record(self.events, journal.KIND_CREATED, client)
            await self.apply()
            return client

    async def delete(self, key: str) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            self.clients.remove(client)
            journal.record(self.events, journal.KIND_DELETED, client)
            await self.apply()
            return True

    async def set_enabled(self, key: str, enabled: bool) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            was_blocked = client.get("disabled_reason") in (quota.QUOTA, quota.EXPIRED)
            if client.get("enabled", True) != enabled:
                journal.record(
                    self.events,
                    journal.KIND_ENABLED if enabled else journal.KIND_DISABLED,
                    client,
                )
            client["enabled"] = enabled
            client["disabled_reason"] = None if enabled else quota.MANUAL
            # Включили того, кого выключил лимит, — начинаем новый период.
            # Иначе следующий же тик выключит его обратно, и кнопка будет
            # выглядеть сломанной.
            if enabled and was_blocked:
                client["quota_used"] = 0
                client["quota_started_at"] = _now()
                if quota.parse_iso(client.get("expires_at")) and \
                        quota.parse_iso(client["expires_at"]) <= datetime.utcnow():
                    client["expires_at"] = None
            if not enabled:
                # Счётчики пира уезжают вместе с ним из интерфейса.
                client["last_seen_rx"] = 0
                client["last_seen_tx"] = 0
            client["updated_at"] = _now()
            await self.apply()
            return True

    async def set_quota(self, key: str, *, limit: int, period: str) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            client["quota_bytes"] = max(0, int(limit))
            client["quota_period"] = period if period in quota.PERIODS else "none"
            client["quota_started_at"] = _now()
            client["updated_at"] = _now()
            await self.apply()
            return True

    async def reset_quota(self, key: str) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            client["quota_used"] = 0
            client["quota_started_at"] = _now()
            if not client.get("enabled", True) and client.get("disabled_reason") == quota.QUOTA:
                client["enabled"] = True
                client["disabled_reason"] = None
            client["updated_at"] = _now()
            await self.apply()
            return True

    # ── Бастион: зоны и апстримы ────────────────────────────────────

    def zone(self, zone_id: str | None) -> Optional[dict[str, Any]]:
        return zones.zone_of({"zone_id": zone_id}, self.zones)

    async def create_zone(
        self, name: str, cidrs: list[str], *, upstream: str | None = None,
        internet: bool = False, exit: str | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            zone = {
                "id": str(uuid.uuid4()),
                "name": name,
                "cidrs": zones.normalize_cidrs(cidrs),
                "upstream": upstream or None,
                "internet": bool(internet),
                # Через какой туннель уходит обычный трафик. Пусто —
                # через сам бастион.
                "exit": exit or None,
                "created_at": _now(),
                "updated_at": _now(),
            }
            self.zones.append(zone)
            await self.apply()
            return zone

    async def update_zone(self, zone_id: str, **fields: Any) -> Optional[dict[str, Any]]:
        async with self._lock:
            zone = zones.zone_of({"zone_id": zone_id}, self.zones)
            if not zone:
                return None
            if "cidrs" in fields:
                fields["cidrs"] = zones.normalize_cidrs(fields["cidrs"])
            for key, value in fields.items():
                if key in ("name", "cidrs", "upstream", "internet", "exit"):
                    zone[key] = value
            zone["updated_at"] = _now()
            await self.apply()
            return zone

    async def delete_zone(self, zone_id: str) -> bool:
        async with self._lock:
            zone = zones.zone_of({"zone_id": zone_id}, self.zones)
            if not zone:
                return False
            self.zones.remove(zone)
            # Клиенты этой зоны остаются без доступа, а не со старым:
            # удалённая зона не должна продолжать что-то открывать.
            for client in self.clients:
                if client.get("zone_id") == zone_id:
                    client["zone_id"] = None
                    client["updated_at"] = _now()
            await self.apply()
            return True

    async def set_zone(self, key: str, zone_id: str | None) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            if zone_id and not zones.zone_of({"zone_id": zone_id}, self.zones):
                return False
            client["zone_id"] = zone_id or None
            client["updated_at"] = _now()
            # Смена зоны — это смена того, куда человек может ходить.
            # В журнале она должна быть видна рядом с его заходами.
            zone = zones.zone_of(client, self.zones)
            journal.record(self.events, journal.KIND_ZONE, client,
                           zone=zone.get("name") if zone else None)
            await self.apply()
            return True

    async def add_upstream(
        self, name: str, conf: str, *, title: str | None = None,
        cidrs: list[str] | None = None,
    ) -> Optional[dict[str, Any]]:
        """Сохранить конфиг провайдера и поднять его.

        Подсети берём из самого конфига, если оператор не указал свои:
        что провайдер разрешил, то и доступно.
        """
        if not upstream.valid_name(name):
            return None
        async with self._lock:
            os.makedirs(upstream.UPSTREAM_DIR, exist_ok=True)
            path = upstream.conf_path(name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(conf)
            os.chmod(path, 0o600)
            item = {
                "name": name,
                "title": title or name,
                "cidrs": zones.normalize_cidrs(cidrs or upstream.parse_allowed(conf)),
                "enabled": True,
                "created_at": _now(),
            }
            self.upstreams = [u for u in self.upstreams if u.get("name") != name]
            self.upstreams.append(item)
            await self.apply()
            return item

    async def update_upstream(self, name: str, **fields: Any) -> Optional[dict[str, Any]]:
        async with self._lock:
            item = next((u for u in self.upstreams if u.get("name") == name), None)
            if not item:
                return None
            if "cidrs" in fields:
                fields["cidrs"] = zones.normalize_cidrs(fields["cidrs"])
            for key, value in fields.items():
                if key in ("title", "cidrs", "enabled"):
                    item[key] = value
            await self.apply()
            return item

    async def delete_upstream(self, name: str) -> bool:
        async with self._lock:
            item = next((u for u in self.upstreams if u.get("name") == name), None)
            if not item:
                return False
            await upstream.down(name)
            self.upstreams.remove(item)
            for path in (upstream.conf_path(name),
                         os.path.join(upstream.UPSTREAM_DIR,
                                      f"{upstream.iface_of(name)}.conf")):
                try:
                    os.remove(path)
                except OSError:
                    pass
            # Зоны, которые ходили через него, остаются, но без туннеля:
            # правила доступа честно перестанут пускать.
            for zone in self.zones:
                if zone.get("upstream") == name:
                    zone["upstream"] = None
                if zone.get("exit") == name:
                    # Выход убрали — обычный трафик возвращается на
                    # адрес бастиона, а не пропадает.
                    zone["exit"] = None
            await self.apply()
            return True

    async def set_rate(self, key: str, rate_bps: int) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            client["rate_bps"] = max(0, int(rate_bps))
            client["updated_at"] = _now()
            await self.apply()
            return True

    async def set_expires(self, key: str, value: Optional[str]) -> bool:
        async with self._lock:
            client = self.find(key)
            if not client:
                return False
            client["expires_at"] = value or None
            if value and not client.get("enabled", True) and \
                    client.get("disabled_reason") == quota.EXPIRED:
                # Срок продлили — клиента возвращаем, пусть решает тик.
                client["enabled"] = True
                client["disabled_reason"] = None
            client["updated_at"] = _now()
            await self.apply()
            return True

    # ── Учёт трафика и применение лимитов ───────────────────────────

    async def tick(self) -> None:
        """Прибавить трафик, пересчитать периоды, выключить перебравших.

        Вызывается раз в QUOTA_TICK_SECONDS. Конфиг переписываем только
        если состав включённых пиров изменился: файл трогать каждые
        десять секунд незачем.
        """
        stats = await awg.peer_stats(force=True)
        now = datetime.utcnow()
        changed_membership = False

        async with self._lock:
            today = now.strftime("%Y-%m-%d")
            for client in self.clients:
                live = stats.get(client.get("public_key")) or {}
                if live:
                    rx = int(live.get("transfer_rx", 0))
                    tx = int(live.get("transfer_tx", 0))
                    d_rx = quota.delta(int(client.get("last_seen_rx") or 0), rx)
                    d_tx = quota.delta(int(client.get("last_seen_tx") or 0), tx)
                    grew = d_rx + d_tx
                    if grew:
                        client["quota_used"] = int(client.get("quota_used") or 0) + grew
                        client["traffic_total"] = int(client.get("traffic_total") or 0) + grew
                        day = client.setdefault("history", {}).setdefault(
                            today, {"rx": 0, "tx": 0}
                        )
                        day["rx"] += d_rx
                        day["tx"] += d_tx
                        _prune_history(client)
                    client["last_seen_rx"] = rx
                    client["last_seen_tx"] = tx

                # Журнал считаем по тем же живым счётчикам: отдельный
                # опрос ради него был бы лишним запуском бинарника раз
                # в десять секунд.
                journal.observe(self.events, client, live, now)

                was_enabled = client.get("enabled", True)
                events = quota.apply(client, now)
                if events:
                    client["updated_at"] = _now()
                    logger.info("клиент %s: %s", client.get("name"), ", ".join(events))
                if client.get("enabled", True) != was_enabled:
                    changed_membership = True
                    if not client.get("enabled", True):
                        client["last_seen_rx"] = 0
                        client["last_seen_tx"] = 0

            if changed_membership:
                await self.apply()
            else:
                await self.persist_state()

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
