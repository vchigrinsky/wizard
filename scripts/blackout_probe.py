#!/usr/bin/env python3
"""Зонд: сбор улик в отрезанной сети, без связи с кем-либо.

    python3 blackout_probe.py             # круг за кругом, пока не остановите
    python3 blackout_probe.py --once      # один проход
    python3 blackout_probe.py --beacons 1.2.3.4,5.6.7.8

Ставится задача, у которой есть неудобное условие: в тот момент, когда
включён режим белых списков, спросить совета не у кого — связи нет. Значит
инструмент должен работать полностью сам, ничего не спрашивать, ничего не
требовать доустанавливать и складывать сырые данные на диск, чтобы разобрать
их потом, вернувшись в нормальную сеть.

Отсюда все решения: один файл, только стандартная библиотека, никаких
аргументов в обязательном порядке, журнал в JSONL рядом со скриптом.

Что именно выясняется
---------------------

Главный вопрос — **на каком уровне закрыто**. Это не праздное любопытство:
от ответа зависит, какую схему обхода вообще имеет смысл строить.

* имя не разрешается в адрес     -> закрыто на DNS
* адрес не отвечает на TCP       -> закрыто на маршрутизации
* TCP есть, приветствие пропадает -> закрыто по имени в рукопожатии (SNI)

Второй по важности — **разрешённое имя на неразрешённом адресе**. Если такое
соединение живёт, значит фильтр смотрит только на имя, и спасает подстановка
имени из белого списка. Если умирает — нужен вход внутри разрешённого
адресного пространства, и никакие ухищрения с именами не помогут.

Третий — **отсечка по объёму**. В известной механике соединение не рвут, а
глушат после первых 16–20 килобайт. Ловится только попыткой прокачать
заметный объём, поэтому маяк по запросу отдаёт мегабайт, а зонд считает,
сколько реально дошло.

На той стороне нужен ``blackout_beacon.py``: он пишет, что до него долетело.
Сопоставив два журнала, можно отличить «наш пакет не ушёл» от «ушёл, дошёл,
а обратно не пустили» — с одной стороны это неразличимо.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)

TIMEOUT = 3.0
WORKERS = 12

#: Имена из белых списков — то, что по общим данным остаётся доступным.
#: Проверяем не на веру, а реально: список собран сообществом и может врать.
WHITELISTED = [
    "gosuslugi.ru", "yandex.ru", "ok.ru", "vk.com", "mail.ru",
    "sberbank.ru", "ozon.ru", "wildberries.ru", "avito.ru", "max.ru",
    "2gis.ru", "dzen.ru", "rutube.ru",
]

#: Контрольная группа: должно быть закрыто. Если вдруг открыто — режим
#: белых списков не включён, и весь замер надо переснимать позже.
CONTROL = ["google.com", "github.com", "cloudflare.com", "telegram.org", "youtube.com"]

#: Резолверы: свой (оператора), публичные зарубежные, публичный российский.
#: По тому, какие живы, видно, насколько глубоко закрыт DNS.
RESOLVERS = {
    "оператор": None,          # берётся из системы
    "google": "8.8.8.8",
    "cloudflare": "1.1.1.1",
    "yandex": "77.88.8.8",
    "quad9": "9.9.9.9",
}

BEACON_TCP = [80, 2053, 8080, 8443, 9443, 40000]
BEACON_UDP = [2053, 8443, 40000, 51820]
BEACON_MARKER = b"BEACON-OK"

BULK_REQUEST = 1024 * 1024      # сколько просим у маяка
BULK_DEADLINE = 12.0            # сколько ждём поток


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


# --- Низкоуровневые пробы --------------------------------------------------


def client_hello(sni: str | None) -> bytes:
    """Настоящее приветствие TLS, но не отправленное, а вынутое в байты."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2   # короче, влезает в один сегмент
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLError:
        pass
    return outgoing.read()


def tcp_probe(ip: str, port: int, payload: bytes = b"", timeout: float = TIMEOUT) -> dict:
    """Одно соединение. Различает способы смерти — это и есть главная ценность."""
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except socket.timeout:
        return {"verdict": "no-tcp", "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"verdict": "no-tcp", "ms": round((time.monotonic() - started) * 1000),
                "error": exc.strerror or str(exc)}
    connect_ms = round((time.monotonic() - started) * 1000)
    if not payload:
        sock.close()
        return {"verdict": "tcp-ok", "ms": connect_ms}
    try:
        sock.sendall(payload)
        data = sock.recv(4096)
        result = {"ms": round((time.monotonic() - started) * 1000),
                  "connect_ms": connect_ms, "got": len(data), "head": data[:16].hex()}
        result["verdict"] = "eof" if not data else "ok"
        if data.startswith(BEACON_MARKER):
            result["beacon"] = True
        return result
    except socket.timeout:
        return {"verdict": "drop", "ms": round((time.monotonic() - started) * 1000),
                "connect_ms": connect_ms}
    except ConnectionResetError:
        return {"verdict": "rst", "ms": round((time.monotonic() - started) * 1000),
                "connect_ms": connect_ms}
    except OSError as exc:
        return {"verdict": "err", "error": str(exc), "connect_ms": connect_ms}
    finally:
        sock.close()


def bulk_probe(ip: str, port: int, sni: str, want: int = BULK_REQUEST) -> dict:
    """Просит у маяка поток и считает, сколько дошло до затыка.

    Именно так ловится «отсечка»: соединение не рвётся, данные просто
    перестают идти. Поэтому меряем не факт ответа, а объём и момент затыка.
    """
    payload = client_hello(sni) + b"BULK %d\n" % want
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.connect((ip, port))
        sock.sendall(payload)
        sock.settimeout(4.0)
        total, last_progress = 0, time.monotonic()
        while total < want and time.monotonic() - started < BULK_DEADLINE:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            except (ConnectionResetError, OSError):
                return {"verdict": "rst", "got": total,
                        "ms": round((time.monotonic() - started) * 1000), "sni": sni}
            if not chunk:
                break
            total += len(chunk)
            last_progress = time.monotonic()
        elapsed = time.monotonic() - started
        verdict = "full" if total >= want else ("stalled" if total else "nothing")
        return {"verdict": verdict, "got": total, "want": want, "sni": sni,
                "ms": round(elapsed * 1000),
                "stall_after_ms": round((last_progress - started) * 1000),
                "kbit": round(total * 8 / max(elapsed, 0.001) / 1000)}
    except OSError as exc:
        return {"verdict": "no-tcp", "error": str(exc), "sni": sni}
    finally:
        sock.close()


def udp_probe(ip: str, port: int, timeout: float = TIMEOUT) -> dict:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.monotonic()
    try:
        sock.sendto(b"PROBE " + os.urandom(4).hex().encode(), (ip, port))
        data, _ = sock.recvfrom(2048)
        return {"verdict": "ok", "got": len(data),
                "beacon": data.startswith(BEACON_MARKER),
                "ms": round((time.monotonic() - started) * 1000)}
    except socket.timeout:
        return {"verdict": "no-answer", "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"verdict": "err", "error": str(exc)}
    finally:
        sock.close()


# --- DNS без внешних библиотек ---------------------------------------------


def system_resolver() -> str | None:
    """Первый nameserver, который назначил провайдер."""
    try:
        out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True,
                             timeout=5).stdout
        found = re.findall(r"nameserver\[0\]\s*:\s*([0-9.]+)", out)
        if found:
            return found[0]
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    return line.split()[1]
    except OSError:
        pass
    return None


def dns_query(resolver: str, name: str, timeout: float = TIMEOUT) -> dict:
    """Запрос A-записи вручную: так видно и сам факт ответа, и его содержимое.

    Через системный resolver этого не увидеть — он прячет и подмену, и то,
    какой именно сервер ответил.
    """
    tid = os.urandom(2)
    header = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    question = b"".join(bytes([len(p)]) + p.encode("ascii")
                        for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.monotonic()
    try:
        sock.sendto(header + question, (resolver, 53))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return {"verdict": "no-answer", "ms": round((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"verdict": "err", "error": str(exc)}
    finally:
        sock.close()

    if data[:2] != tid:
        return {"verdict": "wrong-id"}
    rcode = data[3] & 0x0F
    answers = parse_a_records(data)
    return {
        "verdict": "ok" if answers else ("nxdomain" if rcode == 3 else "empty"),
        "rcode": rcode, "ips": answers,
        "ms": round((time.monotonic() - started) * 1000),
    }


def skip_name(data: bytes, pos: int) -> int:
    while pos < len(data):
        length = data[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:       # сжатие имени — двухбайтовый указатель
            return pos + 2
        pos += 1 + length
    return pos


def parse_a_records(data: bytes) -> list[str]:
    try:
        qd = int.from_bytes(data[4:6], "big")
        an = int.from_bytes(data[6:8], "big")
        pos = 12
        for _ in range(qd):
            pos = skip_name(data, pos) + 4
        found = []
        for _ in range(an):
            pos = skip_name(data, pos)
            rtype = int.from_bytes(data[pos:pos + 2], "big")
            rdlen = int.from_bytes(data[pos + 8:pos + 10], "big")
            rdata = data[pos + 10:pos + 10 + rdlen]
            if rtype == 1 and rdlen == 4:
                found.append(socket.inet_ntoa(rdata))
            pos += 10 + rdlen
        return found
    except (IndexError, ValueError):
        return []


# --- Внешние утилиты -------------------------------------------------------


def run(cmd: list[str], timeout: float = 20.0) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (proc.stdout + proc.stderr).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return f"не выполнилось: {exc}"


def ping(target: str) -> dict:
    out = run(["ping", "-c", "3", "-W", "2000", target], timeout=15)
    match = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    loss = float(match.group(1)) if match else 100.0
    rtt = re.search(r"= ([\d.]+)/([\d.]+)/", out)
    return {"loss": loss, "avg_ms": float(rtt.group(2)) if rtt else None,
            "verdict": "ok" if loss < 100 else "no-answer"}


# --- Где мы находимся ------------------------------------------------------


def beacons_from_ssh_config() -> list[str]:
    """Адреса узлов берём из ~/.ssh/config: там они уже есть, и это избавляет
    от необходимости что-то вводить руками в поле."""
    path = os.path.expanduser("~/.ssh/config")
    if not os.path.exists(path):
        return []
    found = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.lower().startswith("host "):
                match = re.search(r"_(\d+\.\d+\.\d+\.\d+)$", line.split()[1])
                if match:
                    found.append(match.group(1))
    return sorted(set(found))


def my_links() -> list[dict]:
    """Наши собственные маршруты из vless.md / direct.md — чтобы проверить,
    что из уже настроенного вообще подаёт признаки жизни."""
    import urllib.parse

    links = []
    for name in ("vless.md", "direct.md"):
        path = os.path.join(REPO_ROOT, name)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line.startswith("vless://"):
                    continue
                parsed = urllib.parse.urlsplit(line)
                query = urllib.parse.parse_qs(parsed.query)
                links.append({
                    "file": name,
                    "host": parsed.hostname,
                    "port": parsed.port or 443,
                    "sni": query.get("sni", [""])[0],
                    "label": urllib.parse.unquote(parsed.fragment)[:40],
                })
    return links


def environment() -> dict:
    return {
        "local_time": datetime.datetime.now().isoformat(timespec="seconds"),
        "resolver": system_resolver(),
        "route": run(["route", "-n", "get", "default"], timeout=8)[:400],
        "wifi": run(["networksetup", "-getairportnetwork", "en0"], timeout=8)[:120],
    }


# --- Один круг -------------------------------------------------------------


def do_round(beacons: list[str], links: list[dict], deep: bool) -> list[dict]:
    events: list[dict] = [{"kind": "env", **environment()}]
    jobs: list[tuple[dict, callable]] = []

    def add(meta: dict, fn) -> None:
        jobs.append((meta, fn))

    # 1. DNS: кто из резолверов жив и что отвечает
    resolvers = dict(RESOLVERS)
    resolvers["оператор"] = system_resolver()
    for label, server in resolvers.items():
        if not server:
            continue
        for name in (WHITELISTED[:4] + CONTROL[:3]):
            add({"kind": "dns", "resolver": label, "server": server, "name": name},
                lambda s=server, n=name: dns_query(s, n))

    # 2. Что открывается по именам из белого списка и из контрольной группы
    for name in WHITELISTED + CONTROL:
        add({"kind": "site", "name": name},
            lambda n=name: site_probe(n))

    # 3. Маяки: свой адрес, разные порты, разные имена в рукопожатии.
    #    Здесь и лежит главный вопрос — пускают ли по разрешённому имени
    #    на неразрешённый адрес.
    for ip in beacons:
        add({"kind": "beacon-icmp", "ip": ip}, lambda i=ip: ping(i))
        for port in BEACON_TCP:
            add({"kind": "beacon-tcp", "ip": ip, "port": port},
                lambda i=ip, p=port: tcp_probe(i, p, b"PROBE\n"))
        for port in BEACON_UDP:
            add({"kind": "beacon-udp", "ip": ip, "port": port},
                lambda i=ip, p=port: udp_probe(i, p))
        for sni in ("ok.ru", "yandex.ru", "gosuslugi.ru", "example.com", None):
            add({"kind": "beacon-sni", "ip": ip, "port": 8443, "sni": sni or "нет"},
                lambda i=ip, s=sni: tcp_probe(i, 8443, client_hello(s)))

    # 4. Наши собственные маршруты — живы ли
    for link in links:
        add({"kind": "my-route", **link},
            lambda l=link: tcp_probe(l["host"], l["port"], client_hello(l["sni"] or None)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futures = [(meta, pool.submit(fn)) for meta, fn in jobs]
        for meta, future in futures:
            try:
                events.append({**meta, **future.result()})
            except Exception as exc:  # noqa: BLE001 — в поле важнее не упасть
                events.append({**meta, "verdict": "exception", "error": str(exc)})

    # 5. Объём: отсечка ловится только последовательно и не спеша
    if deep:
        for ip in beacons[:2]:
            for sni in ("ok.ru", "example.com"):
                events.append({"kind": "bulk", "ip": ip, "port": 8443,
                               **bulk_probe(ip, 8443, sni)})
        for ip in beacons[:1]:
            events.append({"kind": "traceroute", "ip": ip,
                           "output": run(["traceroute", "-n", "-w", "1", "-q", "1",
                                          "-m", "15", ip], timeout=45)})
    return events


def site_probe(name: str) -> dict:
    """Полная цепочка для одного имени: разрешается ли, отвечает ли,
    доходит ли рукопожатие. Отсюда и берётся уровень, на котором закрыто."""
    try:
        ip = socket.gethostbyname(name)
    except OSError as exc:
        return {"verdict": "no-dns", "error": str(exc)}
    result = tcp_probe(ip, 443, client_hello(name))
    result["ip"] = ip
    if result["verdict"] == "no-tcp":
        result["level"] = "адрес"
    elif result["verdict"] in ("drop", "rst"):
        result["level"] = "имя в рукопожатии"
    elif result["verdict"] == "ok":
        result["level"] = "открыто"
    return result


# --- Итог ------------------------------------------------------------------


def summarize(events: list[dict]) -> None:
    def pick(kind):
        return [e for e in events if e.get("kind") == kind]

    print("\n  --- коротко ---")
    sites = pick("site")
    good = [e for e in sites if e.get("verdict") == "ok"]
    print(f"  сайтов открылось: {len(good)} из {len(sites)}")
    for e in sites:
        mark = "+" if e.get("verdict") == "ok" else "-"
        print(f"    {mark} {e['name']:20} {e.get('verdict','?'):8} {e.get('level','')}")

    dns = pick("dns")
    by_res: dict[str, list[str]] = {}
    for e in dns:
        by_res.setdefault(e["resolver"], []).append(e.get("verdict", "?"))
    print("  DNS:")
    for res, verdicts in by_res.items():
        alive = sum(1 for v in verdicts if v == "ok")
        print(f"    {res:12} ответов {alive}/{len(verdicts)}")

    sni = pick("beacon-sni")
    if sni:
        print("  маяк, разные имена в рукопожатии (главный вопрос):")
        for e in sni:
            print(f"    {e['ip']:16} sni={e['sni']:14} {e.get('verdict','?')}")

    for e in pick("bulk"):
        print(f"  объём: {e['ip']} sni={e.get('sni')} -> {e.get('verdict')}, "
              f"дошло {e.get('got', 0)} б, {e.get('kbit', 0)} кбит/с")


def main() -> int:
    parser = argparse.ArgumentParser(description="Сбор улик в отрезанной сети")
    parser.add_argument("--beacons", help="адреса маяков через запятую")
    parser.add_argument("--once", action="store_true", help="один проход и выход")
    parser.add_argument("--interval", type=float, default=300, help="пауза между кругами, с")
    parser.add_argument("--no-deep", action="store_true",
                        help="без пробы объёма и трассировки (быстрее)")
    parser.add_argument("--out", help="куда писать журнал")
    args = parser.parse_args()

    beacons = ([b.strip() for b in args.beacons.split(",") if b.strip()]
               if args.beacons else beacons_from_ssh_config())
    if not beacons:
        print("не нашёл адресов маяков: укажите --beacons 1.2.3.4,5.6.7.8",
              file=sys.stderr)
        return 2

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out_path = args.out or os.path.join(HERE, f"blackout-probe-{stamp}.jsonl")
    links = my_links()

    print(f"маяков: {len(beacons)} — {', '.join(beacons)}")
    print(f"своих маршрутов на проверку: {len(links)}")
    print(f"журнал: {out_path}")
    print("останавливать — Ctrl+C; журнал можно забирать в любой момент\n")

    round_no = 0
    try:
        while True:
            round_no += 1
            started = time.monotonic()
            print(f"=== круг {round_no}, {now()}")
            events = do_round(beacons, links, deep=not args.no_deep)
            with open(out_path, "a", encoding="utf-8") as fh:
                for event in events:
                    fh.write(json.dumps({"round": round_no, "time": now(), **event},
                                        ensure_ascii=False) + "\n")
            summarize(events)
            print(f"  круг занял {time.monotonic() - started:.0f} с, "
                  f"записано событий: {len(events)}")
            if args.once:
                return 0
            print(f"  следующий через {args.interval:.0f} с\n")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\nостановлено. журнал: {out_path}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
