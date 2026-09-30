"""Mesh-listener — серверная половина связи между агентами.

Апстрим (`upstream.py`) — это КЛИЕНТ: агент дозванивается до чужой сети
и ходит туда сам. Не хватало серверной половины: чтобы СОСЕДНИЙ агент
дозвонился до нас и через нас достал наши ресурсы (IPMI и любой другой
апстрим) или вышел в интернет нашим адресом. Это она.

Интерфейс `awgmesh` слушает порт, принимает пиров-соседей (их раздаёт
контроллер) и форвардит их трафик:
  * до наших ресурсов — маршрут и SNAT уже стоят от `upstream.apply`
    (`10.30.0.0/16 dev up-ipmi` + MASQUERADE на up-ipmi), отдельного
    правила не нужно;
  * в интернет — MASQUERADE через `WG_DEVICE`.

Дозвон в обратную сторону (мы → сосед) отдельного кода не требует: на
нашей стороне это обычный апстрим с endpoint'ом соседского listener'а.

Интерфейс поднимается, только когда есть хотя бы один пир: у обычного
VPN-сервера mesh не должно быть вовсе.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from typing import Any, Optional

from . import awg, config, net

logger = logging.getLogger("mesh")

IFACE = "awgmesh"


async def _run(*args: str, quiet: bool = False) -> tuple[bool, str]:
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    out, _ = await proc.communicate()
    if proc.returncode:
        text = out.decode(errors="replace").strip()
        if not quiet:
            logger.warning("%s → %s", " ".join(args), text[:200])
        return False, text
    return True, out.decode(errors="replace")


def _net(address: str) -> str:
    """Сеть mesh из адреса интерфейса: 10.99.0.1/24 → 10.99.0.0/24."""
    try:
        return str(ipaddress.ip_interface(address).network)
    except ValueError:
        return ""


async def seed(mesh: dict[str, Any]) -> dict[str, Any]:
    """Досеять недостающее: ключ пары и порт. Адрес задаёт контроллер."""
    if not mesh.get("private_key") or not mesh.get("public_key"):
        priv, pub = await awg.keypair()
        mesh["private_key"] = priv
        mesh["public_key"] = pub
    mesh.setdefault("listen_port", config.MESH_PORT)
    mesh.setdefault("address", config.MESH_ADDRESS or None)
    mesh.setdefault("peers", [])
    return mesh


def public(mesh: dict[str, Any]) -> dict[str, Any]:
    """Наружу — без приватного ключа: контроллеру нужен pubkey и порт."""
    return {
        "public_key": mesh.get("public_key"),
        "listen_port": mesh.get("listen_port"),
        "address": mesh.get("address"),
        "peers": [{"name": p.get("name"), "address": p.get("address")}
                  for p in mesh.get("peers") or []],
    }


def _conf_path() -> str:
    # wg-quick называет интерфейс по имени файла — кладём как awgmesh.conf.
    return os.path.join(config.WG_PATH, f"{IFACE}.conf")


async def down(mesh: Optional[dict[str, Any]] = None) -> None:
    """Снять listener. Правила и NAT уходят с ним (они в PostDown конфига)."""
    await _run(config.BIN_QUICK, "down", _conf_path(), quiet=True)
    await _run("ip", "link", "del", IFACE, quiet=True)


async def apply(mesh: dict[str, Any], upstreams: list[dict[str, Any]]) -> None:
    """Поднять/пересобрать mesh-listener под текущих пиров.

    Поднимаем через wg-quick (как апстримы): в образе wg-интерфейсы идут
    через userspace-fallback, голый `ip link add type wireguard` там даёт
    «Protocol not supported». Маршруты не трогаем (Table = off), NAT в
    интернет и форвардинг вешаем в PostUp; до ресурсов SNAT уже стоит на
    их апстрим-интерфейсах.
    """
    peers = [p for p in (mesh or {}).get("peers") or [] if p.get("public_key")]
    address = (mesh or {}).get("address")
    if not peers or not address or not mesh.get("private_key"):
        await down(mesh)
        return

    mnet = _net(address)
    dev = net.egress_device()
    lines = [
        "[Interface]",
        f"Address = {address}",
        f"ListenPort = {int(mesh.get('listen_port') or config.MESH_PORT)}",
        f"PrivateKey = {mesh['private_key']}",
        "Table = off",
        "PostUp = iptables -A FORWARD -i %i -j ACCEPT",
        "PostUp = iptables -A FORWARD -o %i -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "PostDown = iptables -D FORWARD -i %i -j ACCEPT",
        "PostDown = iptables -D FORWARD -o %i -m state --state ESTABLISHED,RELATED -j ACCEPT",
    ]
    if mnet:
        lines.append(f"PostUp = iptables -t nat -A POSTROUTING -s {mnet} -o {dev} -j MASQUERADE")
        lines.append(f"PostDown = iptables -t nat -D POSTROUTING -s {mnet} -o {dev} -j MASQUERADE")
    for p in peers:
        pa = str(p.get("address") or "").split("/")[0]
        if not pa:
            continue
        lines += ["", "[Peer]", f"PublicKey = {p['public_key']}", f"AllowedIPs = {pa}/32"]

    await down(mesh)
    path = _conf_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    ok, err = await _run(config.BIN_QUICK, "up", path)
    if not ok:
        logger.error("mesh: listener не поднялся: %s", err)
        return
    logger.info("mesh: listener на %s, пиров %d", address, len(peers))


async def status(mesh: dict[str, Any]) -> dict[str, Any]:
    """Живость: поднят ли интерфейс и хендшейки с пирами."""
    ok, dump = await _run(config.BIN, "show", IFACE, "dump", quiet=True)
    up = ok
    peers: dict[str, Any] = {}
    if ok:
        import time
        for row in dump.strip().splitlines()[1:]:
            parts = row.split("\t")
            if len(parts) >= 5:
                hs = int(parts[4] or 0)
                peers[parts[0]] = int(time.time() - hs) if hs else None
    return {"up": up, "handshakes": peers}
