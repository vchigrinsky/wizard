#!/usr/bin/env python3
"""Полевой зонд для зоны белых списков: выясняет, ПО ЧЕМУ вас пускают.

    python3 scripts/whitelist_probe.py            # полный прогон, один раз
    python3 scripts/whitelist_probe.py --watch    # по кругу, пока не остановите
    python3 scripts/whitelist_probe.py --quick    # только главная матрица

Связи со мной в этот момент нет, поэтому скрипт ничего не спрашивает, ничего
не требует доустанавливать и сам печатает вывод. Журнал в JSONL пишется рядом,
его я разберу потом.

Главная идея
------------

В зоне белых списков бесполезно выяснять «что работает» — не работает почти
ничего. Полезно выяснить **по какому признаку принимается решение**, потому
что от этого и только от этого зависит, какую схему обхода вообще имеет смысл
строить.

Признаков ровно два: имя в рукопожатии и адрес назначения. Значит нужна
перекрёстная матрица:

                      | адрес разрешённый | адрес наш (не в списке)
    ------------------+-------------------+------------------------
    имя разрешённое   | контроль          | ГЛАВНЫЙ ВОПРОС
    имя не из списка  | ВТОРОЙ ВОПРОС     | контроль

Читается так:

* работает «разрешённое имя на нашем адресе» -> смотрят только имя, и нас
  спасает подстановка SNI. Это лучший исход, он бесплатный;
* работает «чужое имя на разрешённом адресе» -> смотрят только адрес, и надо
  селиться внутри разрешённого адресного пространства;
* не работает ни то ни другое -> проверяют оба, самый тяжёлый случай;
* работает всё -> режим не включён, замер надо переснять позже.

Остальные проверки — DNS, порты, протоколы, объём — нужны, чтобы понять, что
уцелело для аварийного канала, и чтобы отличить «нас фильтруют» от «сеть
лежит».

Нужны маяки
-----------

На узлах должен быть запущен ``blackout_beacon.py`` — он слушает набор портов
и пишет журнал всего, что до него долетело. Это важно: если ответ не вернулся,
запись в его журнале докажет, что наш пакет всё-таки ушёл и дошёл. С одной
стороны эти два случая неразличимы.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from blackout_probe import (  # noqa: E402
    beacons_from_ssh_config,
    bulk_probe,
    client_hello,
    dns_query,
    ping,
    system_resolver,
    udp_probe,
)

TIMEOUT = 3.0
WORKERS = 16

# --- Имена ------------------------------------------------------------------
#
# Список намеренно большой и разбит по смыслу: важно не только «прошло или
# нет», а какая ГРУППА прошла. Одно имя ничего не доказывает — оно могло
# уцелеть случайно; группа из десяти уже говорит о правиле.

SNI_GROUPS: dict[str, list[str]] = {
    "разрешённые: госуслуги и власть": [
        "gosuslugi.ru", "www.gosuslugi.ru", "mos.ru", "nalog.ru",
        "gov.ru", "kremlin.ru", "pos.gosuslugi.ru",
    ],
    "разрешённые: Яндекс": [
        "yandex.ru", "www.yandex.ru", "ya.ru", "dzen.ru",
        "mail.yandex.ru", "market.yandex.ru", "cdn.yandex.ru", "s3.yandex.net",
    ],
    "разрешённые: VK и Mail": [
        "vk.com", "vk.ru", "ok.ru", "mail.ru", "max.ru",
        "userapi.com", "api.vk.com", "sun9-1.userapi.com",
    ],
    "разрешённые: банки": [
        "sberbank.ru", "online.sberbank.ru", "alfabank.ru", "tbank.ru",
        "vtb.ru", "gazprombank.ru",
    ],
    "разрешённые: торговля и сервисы": [
        "ozon.ru", "wildberries.ru", "avito.ru", "2gis.ru",
        "rutube.ru", "kinopoisk.ru", "aliexpress.ru", "dns-shop.ru",
    ],
    "разрешённые: операторы связи": [
        "mts.ru", "beeline.ru", "megafon.ru", "tele2.ru", "rt.ru",
    ],
    # Имена, которые сообщество отобрало опытным путём: именно они стоят в
    # чужих конфигах, помеченных как работающие под белыми списками. Держим
    # отдельной группой — это самая ценная выборка, проверенная не нами.
    "проверенные сообществом": [
        "www.avito.ru", "avito.ru", "vk.com", "vkvideo.ru",
        "rutube.ru", "api-maps.yandex.ru", "iv.kommersant.ru",
    ],
    "заблокированные в РФ": [
        "youtube.com", "www.youtube.com", "googlevideo.com",
        "instagram.com", "facebook.com", "x.com", "twitter.com",
        "telegram.org", "web.telegram.org", "discord.com",
        "rutracker.org", "linkedin.com",
    ],
    "зарубежные нейтральные": [
        "google.com", "www.google.com", "github.com", "cloudflare.com",
        "microsoft.com", "apple.com", "wikipedia.org", "amazon.com",
        "netflix.com", "speedtest.net", "example.com", "iana.org",
    ],
    "регистр: разрешённые": [
        "YANDEX.RU", "Yandex.Ru", "GOSUSLUGI.RU", "OK.RU",
        "www.YANDEX.ru", "VK.COM",
    ],
    "регистр: заблокированные": [
        "YOUTUBE.COM", "WWW.YOUTUBE.COM", "YouTube.Com", "TELEGRAM.ORG",
    ],
    "суффиксные трюки": [
        "yandex.ru.", "gosuslugi.ru.", "vk.com.",
        "notyandex.ru", "notvk.com",
        "yandex.ru.evil-example.net", "gosuslugi.ru.evil-example.net",
        "sub.yandex.ru", "xyz.gosuslugi.ru", "deep.sub.vk.com",
        "yandex.ru.com", "vk.com.ru",
    ],
    "незнакомые и пустые": [
        "zzz-unknown-9x7c1.net", "a1b2c3d4e5.example", "localhost",
        "", None,      # пустая строка и полное отсутствие расширения — разные вещи
    ],
}

#: Что считаем «разрешённым» и «неразрешённым» при подсчёте вердикта.
ALLOWED_GROUPS = [g for g in SNI_GROUPS if g.startswith("разрешённые")]
DISALLOWED_GROUPS = ["заблокированные в РФ", "зарубежные нейтральные"]

# --- Цели -------------------------------------------------------------------

#: Разрешённые сайты — их адреса добываем на месте, они у всех разные.
ALLOWED_SITES = ["yandex.ru", "vk.com", "gosuslugi.ru", "ok.ru", "sberbank.ru"]

#: Заблокированные — чтобы проверить «разрешённое имя на запрещённый адрес».
BLOCKED_SITES = ["youtube.com", "discord.com", "instagram.com"]

#: Нейтральные адреса, которые точно есть и всегда отвечают.
NEUTRAL = {"cloudflare 1.1.1.1": "1.1.1.1", "google 8.8.8.8": "8.8.8.8"}

#: Порты, которые слушает маяк, плюс те, что заняты штатными службами узла.
BEACON_TCP = [80, 2053, 5222, 8080, 8443, 9443, 40000]
BEACON_UDP = [53, 443, 500, 1194, 2053, 8443, 40000, 51820]
NODE_SERVICE_TCP = [22, 443]        # sshd и xray — слушают всегда


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# --- Пробы ------------------------------------------------------------------


def tls_probe(ip: str, port: int, sni: str | None, timeout: float = TIMEOUT) -> dict:
    """Отправляет приветствие TLS с заданным именем и классифицирует смерть."""
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except socket.timeout:
        return {"verdict": "no-tcp", "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"verdict": "no-tcp", "err": exc.strerror or str(exc),
                "ms": round((time.monotonic() - started) * 1000)}
    try:
        sock.sendall(client_hello(sni) if sni != "" else client_hello(None))
        data = sock.recv(4096)
        ms = round((time.monotonic() - started) * 1000)
        if not data:
            return {"verdict": "eof", "ms": ms}
        return {"verdict": "ok", "ms": ms, "got": len(data)}
    except socket.timeout:
        return {"verdict": "drop", "ms": round((time.monotonic() - started) * 1000)}
    except ConnectionResetError:
        return {"verdict": "rst", "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"verdict": "err", "err": str(exc)}
    finally:
        sock.close()


def tcp_probe(ip: str, port: int, timeout: float = TIMEOUT) -> dict:
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        return {"verdict": "open", "ms": round((time.monotonic() - started) * 1000)}
    except socket.timeout:
        return {"verdict": "timeout", "ms": round((time.monotonic() - started) * 1000)}
    except ConnectionRefusedError:
        return {"verdict": "refused", "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"verdict": "err", "err": exc.strerror or str(exc)}
    finally:
        sock.close()


def http_probe(ip: str, host: str, port: int = 80, timeout: float = TIMEOUT) -> dict:
    """Обычный HTTP с подставленным заголовком Host — аналог подмены SNI,
    только для незашифрованного протокола. Иногда фильтры смотрят именно сюда."""
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                     f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode())
        data = sock.recv(2048)
        ms = round((time.monotonic() - started) * 1000)
        if not data:
            return {"verdict": "eof", "ms": ms}
        first = data.split(b"\r\n", 1)[0].decode("ascii", "replace")[:60]
        return {"verdict": "ok", "ms": ms, "ответ": first}
    except socket.timeout:
        return {"verdict": "drop", "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"verdict": "err", "err": str(exc)}
    finally:
        sock.close()


def resolve(name: str) -> tuple[str | None, str]:
    """Адрес имени и то, кто его назвал.

    Спрашивать системный резолвер нельзя: в зоне ограничений он первым и
    начинает врать или молчать, и тогда мы будем стучаться в пустоту, приняв
    это за блокировку. Поэтому сначала опрашиваем публичные резолверы, и
    только если не ответил никто — падаем обратно на системный.
    """
    for label, server in (("google", "8.8.8.8"), ("cloudflare", "1.1.1.1"),
                          ("yandex", "77.88.8.8"), ("quad9", "9.9.9.9")):
        answer = dns_query(server, name, timeout=2.5)
        if answer.get("ips"):
            return answer["ips"][0], label
    try:
        return socket.gethostbyname(name), "системный"
    except OSError:
        return None, "никто"


def run(cmd: list[str], timeout: float = 30) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (p.stdout + p.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return f"(не выполнилось: {exc})"


# --- Фазы -------------------------------------------------------------------


def phase_identity() -> list[dict]:
    egress = run(["curl", "-sS", "--max-time", "10", "https://ipwho.is/"], 15)
    try:
        d = json.loads(egress)
        c = d.get("connection") or {}
        who = f"{d.get('ip')} {d.get('country')} {d.get('city')} AS{c.get('asn')} {c.get('isp')}"
    except ValueError:
        who = f"не определился ({egress[:60]})"
    print(f"  выход:     {who}")
    print(f"  резолвер:  {system_resolver()}")
    return [{"kind": "identity", "egress": who, "resolver": system_resolver(),
             "route": run(["route", "-n", "get", "default"], 8)[:300]}]


def phase_dns() -> tuple[list[dict], dict[str, str]]:
    """Кто из резолверов жив и что отвечает. Заодно добываем адреса целей."""
    resolvers = {"оператор": system_resolver(), "google": "8.8.8.8",
                 "cloudflare": "1.1.1.1", "yandex": "77.88.8.8", "quad9": "9.9.9.9"}
    names = ALLOWED_SITES + BLOCKED_SITES
    events, jobs = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for label, server in resolvers.items():
            if not server:
                continue
            for name in names:
                jobs.append(((label, server, name),
                             pool.submit(dns_query, server, name)))
        for (label, server, name), fut in jobs:
            try:
                events.append({"kind": "dns", "resolver": label, "server": server,
                               "name": name, **fut.result()})
            except Exception as exc:  # noqa: BLE001
                events.append({"kind": "dns", "resolver": label, "name": name,
                               "verdict": "exception", "err": str(exc)})

    alive = {}
    for label in resolvers:
        got = [e for e in events if e.get("resolver") == label]
        ok = sum(1 for e in got if e.get("verdict") == "ok")
        if got:
            print(f"    {label:12} ответов {ok}/{len(got)}")
            alive[label] = f"{ok}/{len(got)}"

    # Расхождение адресов между резолверами — признак подмены ответов.
    for name in names:
        sets = {}
        for e in events:
            if e.get("name") == name and e.get("ips"):
                sets.setdefault(tuple(sorted(e["ips"])), []).append(e["resolver"])
        if len(sets) > 1:
            print(f"    ! {name}: резолверы отвечают по-разному — возможна подмена")
            events.append({"kind": "dns-conflict", "name": name,
                           "варианты": {str(k): v for k, v in sets.items()}})
    return events, alive


def build_targets(beacons: list[str]) -> dict[str, list[tuple[str, str]]]:
    """Собирает цели по классам. Адреса разрешённых и заблокированных сайтов
    добываем через тот резолвер, который жив, — иначе тестировать нечего."""
    targets: dict[str, list[tuple[str, str]]] = {
        "разрешённый сайт": [], "заблокированный сайт": [],
        "наш узел": [], "нейтральный": [],
    }
    for name in ALLOWED_SITES:
        ip, who = resolve(name)
        if ip:
            targets["разрешённый сайт"].append((name, ip))
        else:
            print(f"    ! {name} не разрешился ни у одного резолвера — цель выпала")
    for name in BLOCKED_SITES:
        ip, who = resolve(name)
        if ip:
            targets["заблокированный сайт"].append((name, ip))
            print(f"    {name} -> {ip} (по данным «{who}»)")
        else:
            print(f"    ! {name} не разрешился ни у одного резолвера — цель выпала")
    for ip in beacons:
        targets["наш узел"].append((ip, ip))
    for label, ip in NEUTRAL.items():
        targets["нейтральный"].append((label, ip))
    return targets


def phase_matrix(targets: dict, events: list[dict]) -> dict:
    """Та самая перекрёстная матрица. Ядро всего замера."""
    core = {
        "разрешённое": ["yandex.ru", "gosuslugi.ru", "vk.com", "ok.ru"],
        "заблокированное": ["youtube.com", "telegram.org"],
        "зарубежное": ["google.com", "example.com"],
        "незнакомое": ["zzz-unknown-9x7c1.net"],
        "без имени": [None],
    }
    jobs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for tclass, items in targets.items():
            for tname, ip in items:
                for sclass, snis in core.items():
                    for sni in snis:
                        jobs.append(((tclass, tname, ip, sclass, sni),
                                     pool.submit(tls_probe, ip, 443, sni)))
        for (tclass, tname, ip, sclass, sni), fut in jobs:
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = {"verdict": "exception", "err": str(exc)}
            events.append({"kind": "matrix", "класс цели": tclass, "цель": tname,
                           "ip": ip, "класс имени": sclass, "sni": sni or "нет", **res})

    # Сводка: доля прошедших в каждой клетке.
    cell: dict[tuple[str, str], list[str]] = {}
    for e in events:
        if e.get("kind") != "matrix":
            continue
        cell.setdefault((e["класс цели"], e["класс имени"]), []).append(e["verdict"])

    tclasses = list(targets.keys())
    sclasses = list(core.keys())
    width = max(len(s) for s in sclasses) + 2
    header = "имя / цель".ljust(width)
    print("\n    " + header + "".join(t[:18].ljust(20) for t in tclasses))
    for sclass in sclasses:
        row = sclass.ljust(width)
        for tclass in tclasses:
            v = cell.get((tclass, sclass), [])
            ok = sum(1 for x in v if x == "ok")
            row += (f"{ok}/{len(v)}" if v else "—").ljust(20)
        print(f"    {row}")

    return {(t, s): cell.get((t, s), []) for t in tclasses for s in sclasses}


def phase_big_sni(targets: dict, events: list[dict]) -> None:
    """Большой перебор имён по трём целям: наш узел, разрешённый сайт,
    заблокированный сайт. Полная матрица тут была бы избыточной."""
    picks = []
    for tclass in ("наш узел", "разрешённый сайт", "заблокированный сайт"):
        if targets.get(tclass):
            picks.append((tclass, *targets[tclass][0]))

    jobs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for group, snis in SNI_GROUPS.items():
            for sni in snis:
                for tclass, tname, ip in picks:
                    jobs.append(((group, sni, tclass, tname, ip),
                                 pool.submit(tls_probe, ip, 443, sni)))
        for (group, sni, tclass, tname, ip), fut in jobs:
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = {"verdict": "exception", "err": str(exc)}
            events.append({"kind": "sni", "группа": group, "sni": sni if sni is not None else "нет",
                           "класс цели": tclass, "цель": tname, "ip": ip, **res})

    print(f"\n    {'группа имён'.ljust(34)}" + "".join(t[:16].ljust(18) for t, _, _ in picks))
    for group in SNI_GROUPS:
        row = group.ljust(34)
        for tclass, _, _ in picks:
            got = [e for e in events if e.get("kind") == "sni"
                   and e.get("группа") == group and e.get("класс цели") == tclass]
            ok = sum(1 for e in got if e["verdict"] == "ok")
            row += (f"{ok}/{len(got)}" if got else "—").ljust(18)
        print(f"    {row}")


def phase_ports(beacons: list[str], events: list[dict]) -> None:
    """Что уцелело из портов и протоколов — заготовка под аварийный канал."""
    jobs = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for ip in beacons:
            for port in NODE_SERVICE_TCP + BEACON_TCP:
                jobs.append((("tcp", ip, port), pool.submit(tcp_probe, ip, port)))
            for port in BEACON_UDP:
                jobs.append((("udp", ip, port), pool.submit(udp_probe, ip, port)))
            jobs.append((("icmp", ip, 0), pool.submit(ping, ip)))
        for (proto, ip, port), fut in jobs:
            try:
                res = fut.result()
            except Exception as exc:  # noqa: BLE001
                res = {"verdict": "exception", "err": str(exc)}
            events.append({"kind": "port", "proto": proto, "ip": ip, "port": port, **res})

    for ip in beacons:
        tcp_ok = [e["port"] for e in events if e.get("kind") == "port"
                  and e["ip"] == ip and e["proto"] == "tcp" and e["verdict"] == "open"]
        udp_ok = [e["port"] for e in events if e.get("kind") == "port"
                  and e["ip"] == ip and e["proto"] == "udp" and e["verdict"] == "ok"]
        icmp = [e["verdict"] for e in events if e.get("kind") == "port"
                and e["ip"] == ip and e["proto"] == "icmp"]
        print(f"    {ip:18} tcp: {tcp_ok or '—'}")
        print(f"    {'':18} udp: {udp_ok or '—'}   ping: {icmp[0] if icmp else '?'}")


def phase_extras(targets: dict, beacons: list[str], events: list[dict]) -> None:
    """Объём (отсечка), HTTP с подставленным Host, трассировка."""
    if beacons:
        for sni in ("yandex.ru", "example.com"):
            res = bulk_probe(beacons[0], 8443, sni, want=1024 * 1024)
            events.append({"kind": "bulk", "ip": beacons[0], **res})
            print(f"    объём, имя {sni:14} {res.get('verdict')}, "
                  f"дошло {res.get('got', 0)} б, {res.get('kbit', 0)} кбит/с")

    for tclass in ("наш узел", "разрешённый сайт"):
        for tname, ip in targets.get(tclass, [])[:1]:
            for host in ("yandex.ru", "youtube.com"):
                res = http_probe(ip, host)
                events.append({"kind": "http", "ip": ip, "host": host,
                               "класс цели": tclass, **res})
                print(f"    HTTP на {tclass:18} Host={host:14} {res.get('verdict')}")

    if beacons:
        out = run(["traceroute", "-n", "-w", "1", "-q", "1", "-m", "12", beacons[0]], 40)
        events.append({"kind": "traceroute", "ip": beacons[0], "output": out})


def verdict(cells: dict) -> str:
    """Главный вывод: по какому признаку пускают."""
    def share(tclass: str, sclass: str) -> float:
        v = cells.get((tclass, sclass), [])
        return (sum(1 for x in v if x == "ok") / len(v)) if v else -1.0

    control = share("разрешённый сайт", "разрешённое")
    allowed_on_ours = share("наш узел", "разрешённое")
    foreign_on_allowed = share("разрешённый сайт", "зарубежное")
    unknown_on_ours = share("наш узел", "незнакомое")

    if control < 0:
        return "не удалось построить матрицу — разрешённые сайты не разрешились в адреса"
    if control < 0.5:
        return ("не работают даже разрешённые сайты — это не белые списки, "
                "а полное отсутствие связи. Замер надо переснять")
    if allowed_on_ours >= 0.5 and unknown_on_ours >= 0.5:
        return ("похоже, белые списки НЕ включены: на наш адрес проходит и "
                "разрешённое имя, и незнакомое")
    if allowed_on_ours >= 0.5:
        return ("режим «СМОТРЯТ ТОЛЬКО ИМЯ»: разрешённое имя пускают на наш "
                "адрес. Спасает подстановка SNI, покупать ничего не нужно")
    if foreign_on_allowed >= 0.5:
        return ("режим «СМОТРЯТ ТОЛЬКО АДРЕС»: на разрешённый адрес пускают с "
                "любым именем. Нужен вход внутри разрешённого адресного "
                "пространства, имена не помогут")
    return ("режим «ИМЯ И АДРЕС»: нужно совпадение по обоим признакам. "
            "Самый тяжёлый случай — только вход внутри разрешённого "
            "пространства с разрешённым именем")


# --- Сценарий ---------------------------------------------------------------


def one_round(beacons: list[str], quick: bool, out_path: str, rnd: int) -> None:
    events: list[dict] = []
    started = time.monotonic()

    print(f"\n=== круг {rnd}, {now()}")
    print("\n[1] где мы")
    events += phase_identity()

    print("\n[2] DNS: кто жив и не врёт ли")
    dns_events, _ = phase_dns()
    events += dns_events

    targets = build_targets(beacons)
    for tclass, items in targets.items():
        print(f"    целей «{tclass}»: {len(items)}")

    print("\n[3] ГЛАВНАЯ МАТРИЦА: имя против адреса (прошло/всего)")
    cells = phase_matrix(targets, events)

    if not quick:
        print("\n[4] большой перебор имён")
        phase_big_sni(targets, events)

        print("\n[5] порты и протоколы до наших узлов")
        phase_ports(beacons, events)

        print("\n[6] объём, HTTP с подменой Host, трассировка")
        phase_extras(targets, beacons, events)

    answer = verdict(cells)
    print("\n" + "=" * 72)
    print(f"  ВЫВОД: {answer}")
    print("=" * 72)
    events.append({"kind": "verdict", "текст": answer})

    with open(out_path, "a", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps({"round": rnd, "time": now(), **e},
                                ensure_ascii=False) + "\n")
    print(f"  круг занял {time.monotonic() - started:.0f} с, событий {len(events)}")
    print(f"  журнал: {out_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Полевой зонд для зоны белых списков")
    parser.add_argument("--beacons", help="адреса наших узлов через запятую")
    parser.add_argument("--watch", action="store_true", help="гонять по кругу")
    parser.add_argument("--interval", type=float, default=600, help="пауза между кругами, с")
    parser.add_argument("--quick", action="store_true", help="только главная матрица")
    parser.add_argument("--out", help="куда писать журнал")
    args = parser.parse_args()

    beacons = ([b.strip() for b in args.beacons.split(",") if b.strip()]
               if args.beacons else beacons_from_ssh_config())
    if not beacons:
        print("не нашёл адресов узлов: укажите --beacons 1.2.3.4,5.6.7.8", file=sys.stderr)
        return 2

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.out or os.path.join(HERE, f"whitelist-probe-{stamp}.jsonl")
    print(f"узлов: {len(beacons)} — {', '.join(beacons)}")
    print("останавливать — Ctrl+C; журнал можно забирать в любой момент")

    rnd = 0
    try:
        while True:
            rnd += 1
            one_round(beacons, args.quick, out_path, rnd)
            if not args.watch:
                return 0
            print(f"  следующий круг через {args.interval:.0f} с\n")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nостановлено. журнал: {out_path}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
