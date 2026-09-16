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

    print(f"\n{B}3. Адреса{N}")
    check("сервер занимает первый адрес", render.server_address() == "10.8.0.1")
    check("клиент получает следующий свободный",
          render.next_address({"10.8.0.2", "10.8.0.3"}) == "10.8.0.4")

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

    print(f"\n{B}7. QR{N}")
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
