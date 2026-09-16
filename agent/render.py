"""Сборка конфигов сервера и клиента."""
from __future__ import annotations

import ipaddress
from typing import Any

from . import config, proto


def subnet() -> ipaddress.IPv4Network:
    """Сеть из WG_DEFAULT_ADDRESS вида 10.8.0.x."""
    base = config.WG_DEFAULT_ADDRESS.replace("x", "0")
    return ipaddress.ip_network(f"{base}/24", strict=False)


def server_address() -> str:
    return str(list(subnet().hosts())[0])


def next_address(taken: set[str]) -> str:
    """Первый свободный адрес после серверного."""
    for host in list(subnet().hosts())[1:]:
        if str(host) not in taken:
            return str(host)
    raise RuntimeError("свободные адреса в подсети кончились")


def server_conf(server: dict[str, Any], clients: list[dict[str, Any]]) -> str:
    params = server["params"]
    lines = [
        "# Файл собирает forestsnet awg-agent. Правки руками перезапишутся.",
        "[Interface]",
        f"PrivateKey = {server['private_key']}",
        f"Address = {server_address()}/{subnet().prefixlen}",
        f"ListenPort = {config.WG_PORT}",
    ]
    if config.WG_MTU:
        lines.append(f"MTU = {config.WG_MTU}")
    lines += proto.interface_lines(params)
    if server.get("i1"):
        lines.append(f"I1 = {server['i1']}")

    net = f"{subnet().network_address}/{subnet().prefixlen}"
    lines += [
        "PostUp = " + _nat_rules(net, add=True),
        "PostDown = " + _nat_rules(net, add=False),
    ]

    for client in clients:
        if not client.get("enabled", True):
            continue
        lines += [
            "",
            f"# {client['name']}",
            "[Peer]",
            f"PublicKey = {client['public_key']}",
        ]
        if client.get("preshared_key"):
            lines.append(f"PresharedKey = {client['preshared_key']}")
        lines.append(f"AllowedIPs = {client['address']}/32")
    return "\n".join(lines) + "\n"


def _nat_rules(net: str, *, add: bool) -> str:
    """NAT и форвардинг. Правила снимаются теми же ключами, что ставятся."""
    flag_nat = "-A" if add else "-D"
    dev = config.WG_DEVICE
    iface = config.WG_INTERFACE
    return "; ".join([
        f"iptables -t nat {flag_nat} POSTROUTING -s {net} -o {dev} -j MASQUERADE",
        f"iptables {flag_nat} INPUT -p udp -m udp --dport {config.WG_PORT} -j ACCEPT",
        f"iptables {flag_nat} FORWARD -i {iface} -j ACCEPT",
        f"iptables {flag_nat} FORWARD -o {iface} -j ACCEPT",
    ])


def client_conf(server: dict[str, Any], client: dict[str, Any]) -> str:
    """Конфиг для устройства.

    Параметры обфускации обязаны совпадать с серверными — кроме I1..I5:
    сигнатурный пакет шлёт инициатор, и у каждого клиента он свой.
    """
    params = server["params"]
    host = config.WG_HOST or "СЕРВЕР_НЕ_НАСТРОЕН"
    lines = [
        "[Interface]",
        f"PrivateKey = {client['private_key']}",
        f"Address = {client['address']}/32",
        f"DNS = {config.WG_DEFAULT_DNS}",
    ]
    if config.WG_MTU:
        lines.append(f"MTU = {config.WG_MTU}")
    lines += proto.interface_lines(params)
    if client.get("i1"):
        lines.append(f"I1 = {client['i1']}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server['public_key']}",
    ]
    if client.get("preshared_key"):
        lines.append(f"PresharedKey = {client['preshared_key']}")
    lines += [
        f"AllowedIPs = {config.WG_ALLOWED_IPS}",
        f"Endpoint = {host}:{config.WG_CONFIG_PORT}",
        f"PersistentKeepalive = {config.WG_PERSISTENT_KEEPALIVE}",
    ]
    return "\n".join(lines) + "\n"
