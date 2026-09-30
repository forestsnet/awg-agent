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
import tempfile
from typing import Any, Optional

from . import awg, config

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


async def down(mesh: Optional[dict[str, Any]] = None) -> None:
    """Снять listener и свои правила. mesh нужен, чтобы убрать NAT по сети."""
    await _run("iptables", "-D", "FORWARD", "-i", IFACE, "-j", "ACCEPT", quiet=True)
    await _run("iptables", "-D", "FORWARD", "-o", IFACE, "-m", "state",
               "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT", quiet=True)
    net = _net((mesh or {}).get("address") or "")
    dev = config.WG_DEVICE or "eth0"
    if net:
        await _run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", net,
                   "-o", dev, "-j", "MASQUERADE", quiet=True)
    await _run("ip", "link", "del", IFACE, quiet=True)


async def apply(mesh: dict[str, Any], upstreams: list[dict[str, Any]]) -> None:
    """Поднять/пересобрать mesh-listener под текущих пиров."""
    peers = [p for p in (mesh or {}).get("peers") or [] if p.get("public_key")]
    address = (mesh or {}).get("address")
    if not peers or not address or not mesh.get("private_key"):
        await down(mesh)
        return

    net = _net(address)
    dev = config.WG_DEVICE or "eth0"
    await down(mesh)

    ok, err = await _run("ip", "link", "add", IFACE, "type", "wireguard")
    if not ok:
        logger.error("mesh: интерфейс не создан: %s", err)
        return

    lines = ["[Interface]",
             f"PrivateKey = {mesh['private_key']}",
             f"ListenPort = {int(mesh.get('listen_port') or config.MESH_PORT)}"]
    for p in peers:
        pa = str(p.get("address") or "").split("/")[0]
        if not pa:
            continue
        lines += ["[Peer]", f"PublicKey = {p['public_key']}", f"AllowedIPs = {pa}/32"]
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write("\n".join(lines) + "\n")
        conf_path = fh.name
    try:
        os.chmod(conf_path, 0o600)
        await _run("wg", "setconf", IFACE, conf_path)
    finally:
        os.unlink(conf_path)

    await _run("ip", "address", "add", address, "dev", IFACE, quiet=True)
    await _run("ip", "link", "set", IFACE, "up")

    # Форвардинг трафика соседей и NAT в интернет нашим адресом. До наших
    # ресурсов (апстримов) SNAT уже висит на их интерфейсах.
    await _run("iptables", "-A", "FORWARD", "-i", IFACE, "-j", "ACCEPT", quiet=True)
    await _run("iptables", "-A", "FORWARD", "-o", IFACE, "-m", "state",
               "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT", quiet=True)
    if net:
        await _run("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", net,
                   "-o", dev, "-j", "MASQUERADE", quiet=True)
        await _run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", net,
                   "-o", dev, "-j", "MASQUERADE", quiet=True)
    logger.info("mesh: listener на %s, пиров %d", address, len(peers))


async def status(mesh: dict[str, Any]) -> dict[str, Any]:
    """Живость: поднят ли интерфейс и хендшейки с пирами."""
    ok, dump = await _run("wg", "show", IFACE, "dump", quiet=True)
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
