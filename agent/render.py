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


def subnet6() -> ipaddress.IPv6Network:
    """ULA-подсеть туннеля.

    Считаем её из v4-подсети, чтобы два агента на одной машине (awg и
    wg рядом) не получили одинаковый префикс: 10.8.0.0 → fd0a:0800::/64,
    10.20.0.0 → fd0a:1400::/64.
    """
    if config.WG_SUBNET6:
        return ipaddress.ip_network(config.WG_SUBNET6, strict=False)
    a, b, c, _ = subnet().network_address.packed
    return ipaddress.ip_network(f"fd{a:02x}:{b:02x}{c:02x}::/64", strict=False)


def address6_for(address: str) -> str:
    """v6-адрес клиента — зеркало его v4.

    Номер в подсети один и тот же: 10.8.0.4 → fd0a:0800::4. Так адрес
    остаётся стабильным без отдельного счётчика, а по логам и правилам
    шейпера видно, что это один и тот же клиент.

    Пусто, если v6 выключен или адрес не из нашей подсети (бывает у
    клиентов, переехавших со старой панели с другой сетью).
    """
    if not config.WG_IPV6:
        return ""
    net4 = subnet()
    try:
        ip = ipaddress.ip_address(address.split("/")[0])
    except ValueError:
        return ""
    # Адрес не из нашей сети — считать от неё смещение бессмысленно:
    # так выдали бы v6 из чужого диапазона и запутали и шейпер, и себя.
    if ip not in net4:
        return ""
    offset = int(ip) - int(net4.network_address)
    if offset <= 0:
        return ""
    return str(subnet6().network_address + offset)


def server_address() -> str:
    return str(list(subnet().hosts())[0])


def server_address6() -> str:
    return address6_for(server_address())


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
        f"Address = {_server_addresses()}",
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
        allowed = [f"{client['address']}/32"]
        addr6 = address6_for(client["address"])
        if addr6:
            allowed.append(f"{addr6}/128")
        lines.append("AllowedIPs = " + ", ".join(allowed))
    return "\n".join(lines) + "\n"


def _server_addresses() -> str:
    addrs = [f"{server_address()}/{subnet().prefixlen}"]
    addr6 = server_address6()
    if addr6:
        addrs.append(f"{addr6}/{subnet6().prefixlen}")
    return ", ".join(addrs)


def _nat_rules(cidr: str, *, add: bool) -> str:
    """NAT и форвардинг. Правила снимаются теми же ключами, что ставятся.

    Интерфейс спрашиваем у системы, а не берём из окружения напрямую:
    установщик видит имя хоста, а правило работает внутри контейнера
    (см. net.egress_device).
    """
    flag_nat = "-A" if add else "-D"
    dev = net.egress_device()
    iface = config.WG_INTERFACE
    return "; ".join(_v4_rules(flag_nat, dev, iface, cidr) + _v6_rules(flag_nat, dev, iface))


def _v4_rules(flag_nat: str, dev: str, iface: str, cidr: str) -> list[str]:
    return [
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
    ]


def _v6_rules(flag_nat: str, dev: str, iface: str) -> list[str]:
    """То же для IPv6 — и только когда v6 в туннеле включён.

    NAT66 вешаем лишь при живом глобальном v6 у хоста: без него правило
    бессмысленно, а на машинах, где ip6tables собран без таблицы nat,
    ещё и шумит в логах. Форвардинг и подрезку MSS ставим всегда —
    иначе v6 упрётся в сервер молча и без объяснений.

    `|| true` не для красоты: ip6tables может отсутствовать, а PostUp с
    ненулевым кодом уронит поднятие интерфейса целиком.
    """
    if not config.WG_IPV6:
        return []
    rules = []
    if net.has_global_ipv6():
        cidr6 = f"{subnet6().network_address}/{subnet6().prefixlen}"
        rules.append(
            f"ip6tables -t nat {flag_nat} POSTROUTING -s {cidr6} -o {dev} "
            "-j MASQUERADE || true"
        )
    rules += [
        f"ip6tables -t mangle {flag_nat} FORWARD -o {iface} -p tcp "
        f"--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true",
        f"ip6tables -t mangle {flag_nat} FORWARD -i {iface} -p tcp "
        f"--tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu || true",
        f"ip6tables {flag_nat} FORWARD -i {iface} -j ACCEPT || true",
        f"ip6tables {flag_nat} FORWARD -o {iface} -j ACCEPT || true",
    ]
    return rules


def _client_addresses(client: dict[str, Any]) -> str:
    """Адреса в [Interface] клиента.

    v6 здесь не украшение: без него телефон не поднимает маршрут для
    IPv6 и шлёт его мимо туннеля — вместе с настоящим адресом и мимо
    всех лимитов.
    """
    addrs = [f"{client['address']}/32"]
    addr6 = address6_for(client["address"])
    if addr6:
        addrs.append(f"{addr6}/128")
    return ", ".join(addrs)


def client_conf(
    server: dict[str, Any],
    client: dict[str, Any],
    zone: dict[str, Any] | None = None,
) -> str:
    """Конфиг для устройства.

    Параметры обфускации обязаны совпадать с серверными — кроме I1..I5:
    сигнатурный пакет шлёт инициатор, и у каждого клиента он свой.
    """
    params = server["params"]
    host = config.WG_HOST or "СЕРВЕР_НЕ_НАСТРОЕН"
    lines = [
        "[Interface]",
        f"PrivateKey = {client['private_key']}",
        f"Address = {_client_addresses(client)}",
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
    # У техника с зоной в туннель уходят только её подсети: гонять туда
    # весь интернет незачем — сервер его всё равно не пропустит, а
    # человек увидит «VPN включён, интернета нет».
    from . import zones as _zones

    lines += [
        f"AllowedIPs = {_zones.client_allowed_ips(zone, config.WG_ALLOWED_IPS)}",
        f"Endpoint = {host}:{config.WG_CONFIG_PORT}",
        f"PersistentKeepalive = {config.WG_PERSISTENT_KEEPALIVE}",
    ]
    return "\n".join(lines) + "\n"
