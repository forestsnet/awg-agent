"""Сборка конфигов сервера и клиента."""
from __future__ import annotations

import ipaddress
from typing import Any

from . import config, net, proto


def subnet() -> ipaddress.IPv4Network:
    """Сеть клиентов.

    WG_SUBNET задаётся целиком (`10.8.0.0/16`) — это способ выйти за 253
    адреса, не поднимая второго агента. Если не задана, берём /24 вокруг
    WG_DEFAULT_ADDRESS, как было раньше.
    """
    if config.WG_SUBNET:
        return ipaddress.ip_network(config.WG_SUBNET, strict=False)
    base = config.WG_DEFAULT_ADDRESS.replace("x", "0")
    return ipaddress.ip_network(f"{base}/24", strict=False)


def server_address() -> str:
    return str(list(subnet().hosts())[0])


def next_address(taken: set[str]) -> str:
    """Первый свободный адрес после серверного.

    Идём генератором, а не списком: в /16 адресов шестьдесят пять тысяч,
    и материализовать их в список ради одного свободного — пустая трата
    памяти на каждом создании клиента.
    """
    hosts = subnet().hosts()
    next(hosts, None)  # первый адрес занят сервером
    for host in hosts:
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
    # В режиме обычного WireGuard строк обфускации нет вовсе: wg-quick
    # падает на незнакомом параметре, а не игнорирует его.
    if config.IS_AWG:
        lines += proto.interface_lines(params)
        if server.get("i1"):
            lines.append(f"I1 = {server['i1']}")

    cidr = f"{subnet().network_address}/{subnet().prefixlen}"
    lines += [
        "PostUp = " + _nat_rules(cidr, add=True),
        "PostDown = " + _nat_rules(cidr, add=False),
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


def _nat_rules(cidr: str, *, add: bool) -> str:
    """NAT и форвардинг. Правила снимаются теми же ключами, что ставятся.

    Интерфейс спрашиваем у системы, а не берём из окружения напрямую:
    установщик видит имя хоста, а правило работает внутри контейнера
    (см. net.egress_device).
    """
    flag_nat = "-A" if add else "-D"
    dev = net.egress_device()
    iface = config.WG_INTERFACE
    return "; ".join([
        f"iptables -t nat {flag_nat} POSTROUTING -s {cidr} -o {dev} -j MASQUERADE",
        # Подрезаем MSS под реальный MTU туннеля. Без этого клиент со
        # слишком большим MTU (например, выданный до того, как мы стали
        # его проставлять) отправляет пакеты, которые не пролезают, и
        # получает соединение без трафика.
        f"iptables -t mangle {flag_nat} FORWARD -o {iface} -p tcp "
        f"--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        f"iptables -t mangle {flag_nat} FORWARD -i {iface} -p tcp "
        f"--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
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
    if config.IS_AWG:
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
