"""Проверки агента без докера: параметры, рендер, состояние, ручки.

Запуск: python3 -m tests.test_agent  (из корня репозитория)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

G, R, B, N = "\033[32m", "\033[31m", "\033[36m", "\033[0m"
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    if not ok:
        failures.append(name)
    print(f"  {G}✓{N} {name}" if ok else f"  {R}✗{N} {name}" + (f" — {detail}" if detail else ""))


def _subnet6_for(v4: str) -> str:
    """Префикс v6 для другой v4-подсети — без правки глобального конфига."""
    import ipaddress

    a, b, c, _ = ipaddress.ip_network(v4).network_address.packed
    return f"fd{a:02x}:{b:02x}{c:02x}::/64"


def main() -> None:
    os.environ.setdefault("PASSWORD_HASH", "x")
    from agent import auth, proto, render

    print(f"\n{B}══ awg-agent ══{N}")

    print(f"\n{B}1. Параметры обфускации{N}")
    a = proto.generate(3, random_trailers=True, disable_cookies=True)
    b = proto.generate(3, random_trailers=True, disable_cookies=True)
    # Одинаковые параметры у всех установок — это и есть та примета, по
    # которой блокируют скопом.
    check("две установки получают разные H", a["h1"] != b["h1"] or a["h2"] != b["h2"])
    check("H1..H4 не повторяются внутри установки",
          len({a["h1"], a["h2"], a["h3"], a["h4"]}) == 4)
    # S2 == S1+56 делает handshake-пакеты неразличимыми по длине.
    check("S2 не равен S1+56", a["s2"] != a["s1"] + 56)
    # У 3.0 первые 12 байт padding'а работают как nonce шифрования
    # заголовков: меньше 12 — защита не включится.
    check("S-параметры не меньше 12 на протоколе 3",
          min(a["s1"], a["s2"], a["s3"], a["s4"]) >= 12)

    lines = proto.interface_lines(a)
    text = "\n".join(lines)
    check("3.0: есть ключ заголовков", "HeaderProtectionKey = " in text)
    check("3.1: есть random trailers", "RandomTrailers = on" in text)
    check("3.1: есть disable cookies", "DisableCookies = on" in text)

    two = proto.generate(2, random_trailers=True, disable_cookies=True)
    text2 = "\n".join(proto.interface_lines(two))
    # На 1.x/2.x awg-quick падает на неизвестном параметре, а не
    # игнорирует его — лишние строки ломают установку целиком.
    check("на протоколе 2 строк 3.x нет",
          "HeaderProtectionKey" not in text2 and "RandomTrailers" not in text2)
    check("на протоколе 2 нет и S3/S4", "S3 = " not in text2)

    sigs = {proto.signature_packet() for _ in range(20)}
    check("сигнатурные пакеты разные", len(sigs) >= 18, f"уникальных {len(sigs)}")
    check("сигнатура — пакет CPS, а не число",
          all(s.startswith("<b 0x") for s in sigs))

    print(f"\n{B}2. Конфиги{N}")
    server = {
        "private_key": "kAsWuXaOmJDM7haVp/J5te6xQ7vOaCHRtvs93NQ5tEI=",
        "public_key": "Eg4GyBHY+Z1+yOGww2HdKKB8prdGdtOmgs9tFPI05m8=",
        "params": a, "i1": proto.signature_packet(),
    }
    client = {
        "id": "abc", "name": "iphone", "enabled": True, "address": "10.8.0.2",
        "private_key": "8LYqCvFc7+EI47TQTPzvXIdggH1ANaL7tb2Tm5pDjU4=",
        "public_key": "ZrnwPBUX9b5jREZipXYoWqzDOc/LEcPkrmSg1uRurRI=",
        "preshared_key": "XIrtc7np10zlRnF7uqLwSaE6Kf/GZuHw9/zEOgGj3qM=",
        "i1": proto.signature_packet(),
    }
    srv = render.server_conf(server, [client])
    cli = render.client_conf(server, client)
    check("сервер знает пира", "[Peer]" in srv and client["public_key"] in srv)
    check("у клиента свой I1", f"I1 = {client['i1']}" in cli)
    check("а у сервера свой", f"I1 = {server['i1']}" in srv)
    for key in ("Jc", "S1", "S2", "S3", "S4", "H1", "HeaderProtectionKey"):
        line = next(x for x in srv.split("\n") if x.startswith(key + " "))
        check(f"{key} совпадает у сервера и клиента", line in cli.split("\n"))
    check("выключенный клиент не попадает в конфиг сервера",
          client["public_key"] not in render.server_conf(server, [{**client, "enabled": False}]))
    check("правила NAT снимаются теми же ключами",
          srv.count("-A POSTROUTING") == 1 and srv.count("-D POSTROUTING") == 1)

    # У AmneziaWG 3.x накладные расходы больше классических 60 байт:
    # на MTU 1380 крупные пакеты пропадают целиком, а соединение при
    # этом выглядит живым — хендшейк проходит, ACK'и ходят.
    check("MTU проставлен и серверу, и клиенту",
          "MTU = 1280" in srv and "MTU = 1280" in cli)
    check("MSS подрезается под туннель", "--clamp-mss-to-pmtu" in srv)

    # Установщик крутится на хосте и видит хостовый ens3, а MASQUERADE
    # работает внутри контейнера. Правило с чужим -o не совпадает ни с
    # одним пакетом и не ошибается: хендшейк проходит, трафика нет.
    from agent import config as cfg0, net as netmod

    route = os.path.join(tempfile.mkdtemp(), "route")
    with open(route, "w", encoding="utf-8") as fh:
        fh.write("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n")
        fh.write("wg0\t0000080A\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n")
        fh.write("eth0\t00000000\t010012AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n")
    check("маршрут по умолчанию берётся из /proc, а не из окружения",
          netmod.default_route_device(route) == "eth0")
    check("маршрут в туннель за маршрут по умолчанию не считаем",
          netmod.default_route_device(route) != "wg0")

    was_device, was_present = cfg0.WG_DEVICE, netmod._present
    netmod.reset_cache()
    cfg0.WG_DEVICE = "ens3"
    netmod._present = lambda name: name == "eth0"
    check("хостовый интерфейс, которого тут нет, не берём",
          netmod.egress_device() == "eth0")
    netmod.reset_cache()
    cfg0.WG_DEVICE = "eth1"
    netmod._present = lambda name: name in ("eth0", "eth1")
    check("явно заданный интерфейс уважаем, если он на месте",
          netmod.egress_device() == "eth1")
    netmod._present, cfg0.WG_DEVICE = was_present, was_device
    netmod.reset_cache()

    print(f"\n{B}3. Адреса{N}")
    check("сервер занимает первый адрес", render.server_address() == "10.8.0.1")
    check("клиент получает следующий свободный",
          render.next_address({"10.8.0.2", "10.8.0.3"}) == "10.8.0.4")

    # 253 адреса в /24 — это потолок на агента. Чтобы не поднимать
    # второго ради 300-го клиента, подсеть задаётся целиком.
    from agent import config as cfg1
    cfg1.WG_SUBNET = "10.8.0.0/16"
    check("подсеть берётся из WG_SUBNET", str(render.subnet()) == "10.8.0.0/16")
    check("в ней десятки тысяч адресов", render.subnet().num_addresses - 2 > 65000)
    busy = {f"10.8.0.{i}" for i in range(2, 256)}
    check("за границей /24 выдача продолжается",
          render.next_address(busy).startswith("10.8.1."))
    cfg1.WG_SUBNET = ""

    print(f"\n{B}4. Сессия{N}")
    secret = auth.new_secret()
    token = auth.issue(secret)
    check("своя кука подходит", auth.valid(secret, token))
    check("чужая — нет", not auth.valid(auth.new_secret(), token))
    check("подделанная подпись — нет", not auth.valid(secret, token[:-2] + "xy"))
    check("протухшая — нет", not auth.valid(secret, auth.issue(secret, max_age=-10)))
    check("мусор — нет", not auth.valid(secret, "мусор"))

    print(f"\n{B}5. Импорт из amnezia-wg-easy{N}")
    with tempfile.TemporaryDirectory() as tmp:
        legacy = {
            "server": {"privateKey": "kAsWuXaOmJDM7haVp/J5te6xQ7vOaCHRtvs93NQ5tEI=",
                       "publicKey": "Eg4GyBHY+Z1+yOGww2HdKKB8prdGdtOmgs9tFPI05m8="},
            "clients": {"id-1": {"name": "старый", "enabled": True, "address": "10.8.0.7",
                                 "privateKey": "priv", "publicKey": "pub",
                                 "preSharedKey": "psk", "createdAt": "2026-01-01T00:00:00.000Z"}},
        }
        os.environ["WG_PATH"] = tmp
        with open(os.path.join(tmp, "wg0.json"), "w", encoding="utf-8") as fh:
            json.dump(legacy, fh)

        import importlib
        from agent import config as cfg
        importlib.reload(cfg)
        from agent import render as rnd, state as st
        importlib.reload(rnd)
        importlib.reload(st)

        # Ключи сервера берём как есть: иначе у всех разом перестанут
        # работать уже розданные конфиги.
        async def fake_keypair():
            return "newpriv", "newpub"
        st.awg.keypair = fake_keypair
        st.awg.genpsk = lambda: asyncio.sleep(0, result="psk")
        st.awg.sync = lambda: asyncio.sleep(0)
        st.awg.pubkey = lambda key: asyncio.sleep(0, result="pub-from-priv")

        store = st.Store()
        asyncio.run(store.load())
        check("клиент перенесён", len(store.clients) == 1 and store.clients[0]["name"] == "старый")
        check("адрес сохранён", store.clients[0]["address"] == "10.8.0.7")
        check("ключ сервера не поменялся",
              store.server["private_key"] == legacy["server"]["privateKey"])
        # У старой панели набор параметров кончается на 2.0 — свои
        # генерируем в любом случае.
        check("параметры обфускации свои", bool(store.server["params"].get("header_protection_key")))
        check("клиенту выдан сигнатурный пакет", store.clients[0]["i1"].startswith("<b 0x"))
        check("состояние записано", os.path.exists(os.path.join(tmp, "clients.json")))
        check("конфиг сервера записан", os.path.exists(os.path.join(tmp, "wg0.conf")))
        check("клиент ищется и по имени, и по id",
              store.find("старый") is store.find("id-1") is not None)

        # ── Резервная копия ────────────────────────────────────────
        # Приватные ключи есть только на этой машине: умер VPS — и без
        # копии клиентам раздавать новые конфиги.
        st.shaper.apply = lambda clients: asyncio.sleep(0)
        store.server["session_secret"] = "секрет-сессий"
        dump = store.export_state()
        check("в копии ключ сервера", dump["server"].get("private_key"))
        check("и клиенты с ключами",
              len(dump["clients"]) == 1 and dump["clients"][0].get("private_key"))
        check("секрет сессий в копию не попадает",
              "session_secret" not in dump["server"])

        foreign = json.loads(json.dumps(dump))
        foreign["vpn"] = "wg" if dump["vpn"] == "awg" else "awg"
        try:
            asyncio.run(store.import_state(foreign))
            check("копию от чужого протокола не принимаем", False)
        except ValueError as exc:
            check("копию от чужого протокола не принимаем", "режиме" in str(exc))

        other_net = json.loads(json.dumps(dump))
        other_net["subnet"] = "10.77.0.0/16"
        try:
            asyncio.run(store.import_state(other_net))
            check("копию из чужой подсети тоже", False)
        except ValueError as exc:
            check("копию из чужой подсети тоже", "WG_SUBNET" in str(exc))

        restored = json.loads(json.dumps(dump))
        restored["clients"].append({**dump["clients"][0], "id": "id-2",
                                    "name": "второй", "address": "10.8.0.8"})
        count = asyncio.run(store.import_state(restored))
        check("восстановление ставит клиентов из копии",
              count == 2 and len(store.clients) == 2)
        check("свой секрет сессий остаётся на месте",
              store.server.get("session_secret") == "секрет-сессий")

    print(f"\n{B}6. Лимиты и сроки{N}")
    from datetime import datetime as _dt, timedelta as _td

    from agent import quota

    # Счётчики пира живут ровно до его переустановки: рестарт
    # интерфейса обнуляет их, и разница ушла бы в минус.
    check("обычный прирост", quota.delta(100, 250) == 150)
    check("счётчик обнулился — берём текущий", quota.delta(1000, 30) == 30)
    check("без движения — ноль", quota.delta(500, 500) == 0)

    # «Раз в месяц» для человека — то же число следующего месяца, а не
    # тридцать суток.
    check("день", quota.period_end(_dt(2026, 3, 10, 12), "day") == _dt(2026, 3, 11, 12))
    check("неделя", quota.period_end(_dt(2026, 3, 10), "week") == _dt(2026, 3, 17))
    check("месяц", quota.period_end(_dt(2026, 3, 10), "month") == _dt(2026, 4, 10))
    check("31 января → 28 февраля",
          quota.period_end(_dt(2026, 1, 31), "month") == _dt(2026, 2, 28))
    check("29 февраля → 28 февраля следующего",
          quota.period_end(_dt(2024, 2, 29), "year") == _dt(2025, 2, 28))
    check("без периода — некуда", quota.period_end(_dt(2026, 3, 10), "none") is None)

    now = _dt(2026, 3, 10, 12, 0, 0)
    gb = 1024 ** 3

    over = {"enabled": True, "quota_bytes": gb, "quota_used": gb + 10,
            "quota_period": "none", "quota_started_at": quota.iso(now)}
    check("перебрал лимит — выключаем", "quota_exceeded" in quota.apply(over, now))
    check("причина записана", over["disabled_reason"] == quota.QUOTA)

    # Новый период — клиент возвращается сам, руками ничего не делаем.
    rolled = {"enabled": False, "disabled_reason": quota.QUOTA, "quota_bytes": gb,
              "quota_used": gb + 10, "quota_period": "day",
              "quota_started_at": quota.iso(now - _td(days=1, hours=1))}
    events = quota.apply(rolled, now)
    check("период сброшен", "quota_reset" in events and rolled["quota_used"] == 0)
    check("и клиент включён обратно", rolled["enabled"] and rolled["disabled_reason"] is None)

    # Простой на несколько периодов не должен требовать нескольких тиков.
    stale = {"enabled": True, "quota_bytes": gb, "quota_used": 5, "quota_period": "day",
             "quota_started_at": quota.iso(now - _td(days=5))}
    quota.apply(stale, now)
    check("пропущенные периоды догоняются за один раз",
          quota.parse_iso(stale["quota_started_at"]) > now - _td(days=1))

    expired = {"enabled": True, "expires_at": quota.iso(now - _td(minutes=1))}
    check("срок вышел — выключаем", "expired" in quota.apply(expired, now))
    check("и обратно сам не включится",
          quota.apply(expired, now) == [] and not expired["enabled"])

    # Выключенного руками лимиты не трогают: решение админа сильнее.
    manual = {"enabled": False, "disabled_reason": quota.MANUAL, "quota_bytes": gb,
              "quota_used": 0, "quota_period": "day", "quota_started_at": quota.iso(now)}
    quota.apply(manual, now)
    check("ручное выключение уважается",
          not manual["enabled"] and manual["disabled_reason"] == quota.MANUAL)

    unlimited = {"enabled": True, "quota_bytes": 0, "quota_used": 10 * gb,
                 "quota_period": "none"}
    check("без лимита не выключаем", quota.apply(unlimited, now) == [] and unlimited["enabled"])

    print(f"\n{B}7. Шейпер и история{N}")
    from agent import shaper

    # Номер класса берём из адреса: он обязан быть стабильным, иначе
    # после перестройки клиент попадёт в чужой класс — и в чужую скорость.
    check("класс из адреса стабилен",
          shaper.class_id("10.8.0.5") == shaper.class_id("10.8.0.5/32"))
    check("у разных адресов разные классы",
          shaper.class_id("10.8.0.5") != shaper.class_id("10.8.0.6"))
    check("мусорный адрес не ломает", shaper.class_id("не адрес") == 0)

    # tc читает минорную часть classid как шестнадцатеричное число. Мы
    # подставляли десятичное: 65535 не помещался в 16 бит, класс по
    # умолчанию не создавался, и каждая перестройка писала в лог
    # «invalid class ID».
    check("номер класса уходит в tc шестнадцатеричным",
          shaper.hx(shaper.DEFAULT_CLASSID) == "ffff" and shaper.hx(32) == "20")
    # Правила живут в ядре и исчезают вместе с интерфейсом: после
    # обновления или ребута лимиты переставали действовать до первой
    # правки клиента. Со стороны — «ограничение не работает».
    main_src = open(os.path.join(ROOT, "agent", "main.py"), encoding="utf-8").read()
    state_src = open(os.path.join(ROOT, "agent", "state.py"), encoding="utf-8").read()
    # Вместе с шейпером в ядре живут зоны и туннели провайдеров: после
    # перезапуска контейнера их тоже нужно поднять, иначе зоны
    # открываются, а апстримы остаются опущенными.
    check("на старте правила накатываются целиком",
          "await store.reapply()" in main_src and "async def reapply" in state_src)

    # Всплеск меньше пары десятков килобайт режет мелкие пачки пакетов:
    # TCP не разгоняется, и человек видит «медленно» на выданной скорости.
    check("всплеск не меньше 32 КБ", shaper.burst_bytes(1_000_000) >= 32 * 1024)
    check("всплеск растёт со скоростью",
          shaper.burst_bytes(100_000_000) > shaper.burst_bytes(10_000_000))

    # История обрезается по датам, а не по числу записей: дни простоя в
    # неё не попадают, и «последние 90 записей» растянулись бы на годы.
    from agent import config as cfg2, state as st2
    old_days = cfg2.HISTORY_DAYS
    cfg2.HISTORY_DAYS = 3
    client = {"history": {f"2026-01-0{i}": {"rx": i, "tx": 0} for i in range(1, 8)}}
    st2._prune_history(client)
    check("история подрезана", len(client["history"]) == 3)
    check("выброшены самые старые", "2026-01-01" not in client["history"]
          and "2026-01-07" in client["history"])
    cfg2.HISTORY_DAYS = old_days

    print(f"\n{B}8. IPv6 в туннеле{N}")
    # Живая история: у клиента в AllowedIPs стоит ::/0, а v6-адреса у
    # туннеля нет. iOS поднимает маршрут для v6, только если адрес есть,
    # поэтому весь IPv6 шёл мимо VPN — напрямую через оператора. Со
    # стороны это выглядело как «ограничение скорости не работает»:
    # speedtest уезжал по v6 и показывал скорость сотовой сети.
    from agent import config as cfg6, net as net6
    from agent import render as rnd6

    os.environ["WG_SUBNET"] = "10.8.0.0/16"
    check("подсеть v6 считается из v4",
          str(rnd6.subnet6()) == "fd0a:800::/64", str(rnd6.subnet6()))
    check("у экземпляров разные префиксы", _subnet6_for("10.20.0.0/16") != str(rnd6.subnet6()))
    check("сервер занимает ::1", rnd6.server_address6() == "fd0a:800::1")
    check("адрес клиента — зеркало v4",
          rnd6.address6_for("10.8.0.4") == "fd0a:800::4")
    check("чужой адрес не получает v6", rnd6.address6_for("192.168.1.5") == "")

    # Параметры обфускации берём настоящие: в awg-режиме рендер без них
    # не собирается, а режим по умолчанию — именно awg.
    srv6 = {"private_key": "k", "public_key": "p", "params": proto.generate(3, random_trailers=True, disable_cookies=False),
            "i1": proto.signature_packet()}
    cli6 = {"name": "c", "public_key": "pp", "private_key": "x",
            "address": "10.8.0.4", "enabled": True}
    conf6 = rnd6.client_conf(srv6, cli6)
    check("v6 попал в конфиг клиента", "fd0a:800::4/128" in conf6, conf6.split("\n")[2])
    server_conf6 = rnd6.server_conf(srv6, [cli6])
    check("и в адрес сервера", "fd0a:800::1/64" in server_conf6)
    check("и в AllowedIPs пира", "fd0a:800::4/128" in server_conf6)
    check("форвардинг v6 поднимается", "ip6tables -A FORWARD -i" in server_conf6)
    # ip6tables может не быть вовсе, а ненулевой код в PostUp уронит
    # поднятие интерфейса целиком.
    check("v6-правила не роняют интерфейс", "|| true" in server_conf6)

    # NAT66 вешаем только при живом глобальном v6 у хоста: иначе правило
    # бессмысленно, а на части ядер ещё и шумит.
    real_v6 = net6.has_global_ipv6
    net6.has_global_ipv6 = lambda *a, **kw: True
    check("с глобальным v6 включается NAT66",
          "ip6tables -t nat -A POSTROUTING" in rnd6.server_conf(srv6, [cli6]))
    net6.has_global_ipv6 = lambda *a, **kw: False
    check("без него NAT66 не ставим",
          "ip6tables -t nat" not in rnd6.server_conf(srv6, [cli6]))
    net6.has_global_ipv6 = real_v6

    # Рубильник: если v6 в туннеле где-то мешает, его выключают одной
    # переменной — и конфиг снова строго v4.
    cfg6.WG_IPV6 = False
    check("рубильник выключает v6 целиком",
          "fd0a" not in rnd6.client_conf(srv6, cli6)
          and "ip6tables" not in rnd6.server_conf(srv6, [cli6]))
    cfg6.WG_IPV6 = True

    print(f"\n{B}9. Бастион: зоны и апстримы{N}")
    # Задача: три техника и доступ к IPMI через один конфиг, который не
    # хочется раздавать. Разные `AllowedIPs` в файлах — не ограничение,
    # а просьба: файл лежит у человека. Поэтому решает сервер.
    import asyncio as _aio

    from agent import upstream as ups
    from agent import zones as zn

    print(f"\n{B}  · разбор подсетей{N}")
    check("одиночный адрес считается /32", zn.valid_cidr("10.30.247.190") == "10.30.247.190/32")
    check("мусор отбрасывается", zn.valid_cidr("ipmi.local") is None)
    check("дубли схлопываются",
          zn.normalize_cidrs(["10.30.0.0/16", "10.30.0.0/16", "нет"]) == ["10.30.0.0/16"])

    zone = {"id": "z1", "name": "IPMI", "cidrs": ["10.30.0.0/16"], "internet": False}
    print(f"\n{B}  · что уезжает клиенту{N}")
    check("технику — только его подсети",
          zn.client_allowed_ips(zone, "0.0.0.0/0, ::/0") == "10.30.0.0/16")
    check("с интернетом — как обычно",
          zn.client_allowed_ips({**zone, "internet": True}, "0.0.0.0/0") == "0.0.0.0/0")
    check("без зоны ничего не меняется",
          zn.client_allowed_ips(None, "0.0.0.0/0") == "0.0.0.0/0")

    print(f"\n{B}  · правила на сервере{N}")
    calls: list[str] = []

    async def _fake_run(*args, quiet=False):
        calls.append(" ".join(args))
        return True

    real_run, zn._run = zn._run, _fake_run
    zn._installed = False
    try:
        _aio.run(zn.apply(
            [{"address": "10.8.0.2", "zone_id": "z1"},
             {"address": "10.8.0.3", "zone_id": None}],
            [zone, {"id": "z2", "cidrs": ["194.36.177.0/24"]}],
        ))
    finally:
        zn._run = real_run
    joined = "\n".join(calls)
    check("технику открыта его подсеть",
          "-A FSNT-ZONES -s 10.8.0.2/32 -d 10.30.0.0/16 -j ACCEPT" in joined)
    # Главное во всей затее: чужая зона закрыта, даже если техник
    # пропишет её себе в конфиг руками.
    check("чужая зона ему закрыта",
          "-A FSNT-ZONES -s 10.8.0.2/32 -d 194.36.177.0/24 -j DROP" in joined)
    check("зона без интернета не выпускает наружу",
          "-A FSNT-ZONES -s 10.8.0.2/32 -j DROP" in joined)
    # Обычный клиент VPN не должен видеть служебные сети только потому,
    # что сервер до них дотягивается.
    check("клиент без зоны в служебные сети не ходит",
          "-A FSNT-ZONES -s 10.8.0.3/32 -d 10.30.0.0/16 -j DROP" in joined)
    check("ответы установленных соединений пропускаем",
          "conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" in joined)
    check("цепочка подключена первой", "-I FORWARD 1" in joined)

    # Последнюю зону удалили — правила обязаны сняться, иначе доступ
    # останется у тех, у кого его больше нет.
    calls.clear()
    zn._run = _fake_run
    try:
        _aio.run(zn.apply([{"address": "10.8.0.2"}], []))
    finally:
        zn._run = real_run
    check("удаление последней зоны снимает правила",
          any("-D FORWARD" in c for c in calls) and any("-X" in c for c in calls))

    # А сервер, у которого зон никогда не было, iptables вообще не
    # трогает: у обычного VPN их нет, и лишние вызовы — только шум в
    # логе на каждое изменение клиента.
    calls.clear()
    zn._installed = False
    zn._run = _fake_run
    try:
        _aio.run(zn.apply([{"address": "10.8.0.2"}], []))
    finally:
        zn._run = real_run
    check("без зон сервер живёт как раньше", calls == [], str(calls[:2]))

    print(f"\n{B}  · выходная нода{N}")
    # Техник лезет на клиентские машины для диагностики: светить туда
    # свой домашний адрес не надо, поэтому обычный трафик можно увести
    # в выбранный туннель.
    exit_zone = {"id": "z9", "name": "Диагностика", "cidrs": ["10.60.0.0/16"],
                 "internet": True, "exit": "tube"}
    check("выход зоны читается", zn.exit_of(exit_zone) == "tube")
    check("без интернета выход не имеет смысла",
          zn.exit_of({**exit_zone, "internet": False}) is None)
    check("без выхода — через сам бастион", zn.exit_of({**exit_zone, "exit": None}) is None)

    calls.clear()
    zn._routing_installed = False
    zn._run = _fake_run
    try:
        _aio.run(zn.apply(
            [{"address": "10.8.0.7", "zone_id": "z9"},
             {"address": "10.8.0.8", "zone_id": "z1"}],
            [exit_zone, zone],
            [{"name": "tube"}],
        ))
    finally:
        zn._run = real_run
    joined = "\n".join(calls)
    check("трафик техника уходит в туннель",
          "ip rule add from 10.8.0.7/32 lookup 170" in joined, joined[:200])
    # Главное: основную таблицу не трогаем, иначе туда же уедет трафик
    # самого сервера вместе с нашим SSH.
    check("своя таблица, а не основная",
          "ip route replace default dev up-tube table 170" in joined)
    check("остальных не трогаем", "10.8.0.8/32 lookup" not in joined)

    print(f"\n{B}  · апстримы{N}")
    conf = (
        "[Interface]\nPrivateKey = k\nAddress = 10.40.0.126/24\n"
        "Table = 42\n\n[Peer]\nPublicKey = p\n"
        "AllowedIPs = 10.30.0.0/16, 10.40.0.0/24, 0.0.0.0/0\n"
        "Endpoint = mgmt.example.com:13231\n"
    )
    check("подсети берём из конфига провайдера",
          ups.parse_allowed(conf) == ["10.30.0.0/16", "10.40.0.0/24"])
    prepared = ups.prepare_conf(conf)
    # Иначе конфиг с 0.0.0.0/0 уведёт в чужой туннель весь трафик
    # сервера — вместе с клиентами и нашим же SSH.
    check("маршруты wg-quick выключены", "Table = off" in prepared)
    check("чужая Table = 42 убрана", "Table = 42" not in prepared)
    # wg-quick зовёт для строки DNS resolvconf, которого в контейнере
    # нет: он сносит уже поднятый интерфейс и возвращает ошибку —
    # апстрим не поднимается вовсе. А там, где resolvconf есть,
    # провайдерский DNS прописался бы всему серверу.
    with_dns = conf.replace("[Peer]", "DNS = 1.1.1.1\n\n[Peer]")
    check("DNS провайдера не уезжает на сервер",
          "DNS" not in ups.prepare_conf(with_dns))
    check("имя интерфейса влезает в ядро", len(ups.iface_of("tube-hosting")) <= 15)
    check("кривое имя не принимается",
          not ups.valid_name("../etc/passwd") and not ups.valid_name("имя"))
    check("нормальное принимается", ups.valid_name("tube-host"))
    # Приватный ключ провайдера наружу не отдаём ни при каких условиях.
    safe = ups.sanitize({"name": "tube", "cidrs": ["10.30.0.0/16"], "conf": conf})
    check("конфиг наружу не уходит", "conf" not in safe and "PrivateKey" not in str(safe))

    print(f"\n{B}10. Журнал подключений{N}")
    # «Последнее рукопожатие» отвечает только на «сейчас он тут?».
    # Для служебного доступа нужна история: когда заходил, сколько
    # пробыл и с какого адреса — разбор инцидента начинается с этого.
    from datetime import datetime as _dt, timedelta as _td

    from agent import journal as jr

    events: list = []
    tech = {"id": "c1", "name": "Сергей", "address": "10.8.0.2",
            "zone_id": "z1", "last_seen_rx": 0, "last_seen_tx": 0}
    t0 = _dt(2026, 9, 19, 10, 0, 0)

    jr.observe(events, tech, {"latest_handshake_at": t0, "endpoint": "5.5.5.5:1234",
                              "transfer_rx": 0, "transfer_tx": 0}, t0)
    check("подключение записано", events[-1]["kind"] == "connected", str(events[-1:]))
    check("видно, откуда пришёл", events[-1]["endpoint"] == "5.5.5.5:1234")

    tech["last_seen_rx"], tech["last_seen_tx"] = 1_000_000, 2_000_000
    t1 = t0 + _td(minutes=20)
    jr.observe(events, tech, {"latest_handshake_at": t1, "endpoint": "5.5.5.5:1234",
                              "transfer_rx": 1_000_000, "transfer_tx": 2_000_000}, t1)
    check("живая сессия не плодит записей", len(events) == 1, str(len(events)))

    # Тишина дольше IDLE_GAP — человек ушёл.
    t2 = t1 + _td(minutes=10)
    jr.observe(events, tech, {}, t2)
    last = events[-1]
    check("отключение записано", last["kind"] == "disconnected")
    # Длительность считаем до последнего рукопожатия, иначе к каждой
    # сессии приклеивались бы минуты ожидания.
    check("длительность без хвоста ожидания", last["seconds"] == 20 * 60, str(last))
    check("трафик сессии посчитан", last["rx"] == 1_000_000 and last["tx"] == 2_000_000)
    check("сессия закрыта", "session" not in tech)

    # Переезд в другую сеть — новая сессия, а не продолжение старой.
    jr.observe(events, tech, {"latest_handshake_at": t2, "endpoint": "5.5.5.5:1234",
                              "transfer_rx": 1_000_000, "transfer_tx": 2_000_000}, t2)
    t3 = t2 + _td(minutes=5)
    jr.observe(events, tech, {"latest_handshake_at": t3, "endpoint": "7.7.7.7:999",
                              "transfer_rx": 1_100_000, "transfer_tx": 2_100_000}, t3)
    kinds = [e["kind"] for e in events[-3:]]
    check("смена сети закрывает сессию и открывает новую",
          kinds == ["connected", "disconnected", "connected"], str(kinds))
    check("причина указана", events[-2].get("reason") == "сменил сеть")

    jr.record(events, jr.KIND_ZONE, tech, zone="IPMI")
    check("смена зоны попадает в журнал", events[-1]["kind"] == "zone")
    check("выборка свежим вперёд",
          jr.select(events, limit=2)[0]["kind"] == "zone")
    check("можно отобрать одного человека",
          len(jr.select(events, client_id="c1")) == len(events))
    check("и чужого не подмешать", jr.select(events, client_id="нет") == [])

    # Журнал живёт в файле состояния, который читается целиком на
    # каждом старте: за год он превратил бы его в мегабайты.
    many: list = []
    for i in range(jr.LIMIT + 50):
        jr.record(many, jr.KIND_CONNECTED, tech, endpoint=f"1.1.1.{i % 250}")
    check("журнал подрезан", len(many) == jr.LIMIT, str(len(many)))

    print(f"\n{B}  · имя файла{N}")
    # Имя клиента пишет человек: «Сергей — дежурный» валил выдачу
    # конфига пятисоткой — в заголовки HTTP помещается только latin-1.
    from agent.main import _attachment

    head = _attachment("Сергей — дежурный", ".conf")["Content-Disposition"]
    check("заголовок кодируется latin-1", bool(head.encode("latin-1")))
    check("русское имя сохранено", "filename*=UTF-8''" in head)
    check("есть простое имя для старых клиентов", 'filename="' in head)

    print(f"\n{B}11. QR{N}")
    # segno отдаёт svg БАЙТАМИ: на текстовом буфере ручка падала 500-й,
    # и это выяснилось уже на живой панели.
    import io as _io

    try:
        import segno
    except ImportError:
        # Локально без установленных зависимостей проверка пропускается,
        # в CI они ставятся и она отрабатывает.
        print("  · пропущено: segno не установлен")
        segno = None

    buf = _io.BytesIO() if segno else None
    if segno:
        segno.make(cli, error="m").save(buf, kind="svg", scale=5, border=2,
                                        dark="#0f172a", light="#ffffff")
        data = buf.getvalue()
        check("qr отдаётся байтами", isinstance(data, bytes) and len(data) > 500)
        check("это действительно svg",
              data.lstrip()[:4] == b"<?xm" or b"<svg" in data[:200])

    if failures:
        print(f"\n{R}Провалено: {len(failures)}{N}")
        for f in failures:
            print(f"  {R}·{N} {f}")
        raise SystemExit(1)
    print(f"\n{G}Все проверки пройдены{N}\n")


if __name__ == "__main__":
    main()
