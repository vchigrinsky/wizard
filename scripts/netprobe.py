#!/usr/bin/env python3
"""Зонд для поиска места и признака, по которому режется соединение.

Скрипт самодостаточный: ни одной внешней зависимости, только стандартная
библиотека. Копируется на любой узел и запускается там же — именно так и
задумано, потому что интересна не наша машина, а конкретный участок пути.

    python3 netprobe.py 109.104.153.242 185.11.134.248        # матрица проб
    python3 netprobe.py 109.104.153.242 --cases tls:www.google.com --repeat 5
    python3 netprobe.py 109.104.153.242 --ttl-scan tls:www.google.com

Идея
----

Соединение может умирать по-разному, и различать эти способы важнее, чем
знать сам факт «не работает»:

* **timeout** — пакет проглотили молча. Классический ``drop`` на фильтре.
* **rst** — соединение убили инъекцией TCP RST. Другой механизм, другой
  производитель железа, лечится иначе.
* **eof** — вторая сторона закрыла соединение штатно.
* **ok** — ответ пришёл.

Чтобы понять, по какому признаку срабатывает фильтр, нужно менять по одному:
адрес, порт, наличие и значение SNI, размер и содержимое первого пакета,
разбит ли он на сегменты. Каждая «проба» (case) — это ровно один такой
вариант, а таблица проб по нескольким адресам сразу показывает, что именно
отличает заблокированное направление от рабочего.

Пробы
-----

``tcp``               только рукопожатие TCP, полезной нагрузки нет
``tls:<sni>``         настоящий TLS ClientHello с этим SNI, одним пакетом
``tls-nosni``         ClientHello без расширения SNI
``tls-split:<sni>``   тот же ClientHello, разрезанный на два сегмента с паузой
``tls-slice:<sni>:<n>`` ClientHello, порезанный на куски по n байт
``raw:<n>``           n случайных байт (проверка «дело в TLS или в объёме»)
``http:<host>``       обычный HTTP-запрос
``clean:<sni>``       ClientHello с SNI, но целевой адрес — настоящий владелец
                      имени (контроль: работает ли TLS в принципе)

Локализация по TTL
------------------

``--ttl-scan`` отправляет полезную нагрузку с искусственно заниженным TTL:
пакет умирает по дороге, не дойдя ни до фильтра, ни до сервера. Наименьший
TTL, при котором соединение всё-таки оказывается «отравлено», равен числу
хопов до фильтра. Сразу после пробы шлётся безобидный маркер с нормальным
TTL — по тому, дошёл ли он (видно в tcpdump на дальнем конце) и не оборвалось
ли соединение, и определяется, увидел ли фильтр нашу нагрузку.
"""

from __future__ import annotations

import argparse
import os
import random
import socket
import ssl
import struct
import sys
import time

DEFAULT_CASES = [
    "tcp",
    "tls:www.google.com",
    "tls-nosni",
    "tls:example.com",
    "tls-split:www.google.com",
    "raw:517",
    "http:example.com",
]

READ_TIMEOUT = 6.0
CONNECT_TIMEOUT = 6.0


# --- Сборка полезной нагрузки ---------------------------------------------


def client_hello(sni: str | None, tls12: bool = False) -> bytes:
    """Настоящий ClientHello, но не отправленный в сеть, а вынутый в байты.

    Собирать TLS руками не хочется — получится непохожий на настоящий
    отпечаток, и фильтр отреагирует не на то. Поэтому берём штатный ssl,
    подсовываем ему память вместо сокета и забираем то, что он собирался
    отправить первым пакетом.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if tls12:
        # Без TLS 1.3 не уезжает key_share, и приветствие ужимается в пару
        # сотен байт — ближе к тому, что шлёт браузер или Reality.
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    try:
        obj.do_handshake()
    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
        pass
    except ssl.SSLError:
        pass
    return outgoing.read()


def build_payload(case: str) -> tuple[list[bytes], str]:
    """Возвращает список сегментов для отправки и человеческое описание."""
    name, _, arg = case.partition(":")

    if name == "tcp":
        return [], "рукопожатие TCP без нагрузки"
    if name == "tls":
        return [client_hello(arg)], f"ClientHello, SNI={arg}"
    if name == "tls12":
        return [client_hello(arg, tls12=True)], f"короткий ClientHello TLS 1.2, SNI={arg}"
    if name == "tls-nosni":
        return [client_hello(None)], "ClientHello без SNI"
    if name == "clean":
        return [client_hello(arg)], f"ClientHello, SNI={arg} (контроль)"
    if name == "tls-split":
        data = client_hello(arg)
        cut = 8  # SNI гарантированно уезжает во второй сегмент
        return [data[:cut], data[cut:]], f"ClientHello SNI={arg}, разрез на {cut} байте"
    if name == "tls-slice":
        sni, _, size = arg.partition(":")
        step = int(size or 40)
        data = client_hello(sni)
        return (
            [data[i : i + step] for i in range(0, len(data), step)],
            f"ClientHello SNI={sni}, куски по {step} байт",
        )
    if name == "raw":
        size = int(arg or 517)
        return [bytes(random.getrandbits(8) for _ in range(size))], f"{size} случайных байт"
    if name == "http":
        host = arg or "example.com"
        body = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\n\r\n"
        return [body.encode()], f"HTTP-запрос, Host={host}"
    raise SystemExit(f"неизвестная проба: {case}")


# --- Одна проба ------------------------------------------------------------


class Result:
    def __init__(self, verdict: str, connect_ms: float, total_ms: float, got: bytes, note: str = ""):
        self.verdict = verdict
        self.connect_ms = connect_ms
        self.total_ms = total_ms
        self.got = got
        self.note = note

    def describe(self) -> str:
        head = ""
        if self.got:
            if self.got[:1] == b"\x16" and self.got[1:2] == b"\x03":
                head = "ServerHello"
            elif self.got[:1] == b"\x15":
                head = "TLS alert"
            elif self.got[:4] in (b"HTTP",):
                head = self.got.split(b"\r\n", 1)[0].decode("ascii", "replace")
            else:
                head = self.got[:12].hex()
        bits = [f"{self.verdict:8}", f"connect {self.connect_ms:6.0f}мс", f"итого {self.total_ms:6.0f}мс"]
        if self.got:
            bits.append(f"{len(self.got)}б {head}")
        if self.note:
            bits.append(self.note)
        return "  ".join(bits)


def probe(
    ip: str,
    port: int,
    case: str,
    *,
    ttl: int | None = None,
    marker: bytes | None = None,
    gap: float = 0.05,
    read_timeout: float = READ_TIMEOUT,
) -> Result:
    segments, _ = build_payload(case)
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((ip, port))
    except socket.timeout:
        return Result("no-tcp", (time.monotonic() - started) * 1000, 0, b"", "TCP не установился")
    except OSError as exc:
        return Result("no-tcp", (time.monotonic() - started) * 1000, 0, b"", str(exc))
    connect_ms = (time.monotonic() - started) * 1000

    note = ""
    try:
        if ttl is not None:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        for i, chunk in enumerate(segments):
            if i:
                time.sleep(gap)
            sock.sendall(chunk)
        if ttl is not None:
            # Возвращаем нормальный TTL и шлём маркер: он доедет до сервера,
            # если фильтр ещё не отравил соединение.
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
            if marker:
                time.sleep(0.02)
                sock.sendall(marker)
                note = f"маркер {len(marker)}б отправлен"

        if not segments:
            # Проба «только TCP»: ждать нечего, сервер сам первым не заговорит.
            return Result("tcp-ok", connect_ms, (time.monotonic() - started) * 1000, b"", note)

        sock.settimeout(read_timeout)
        got = b""
        try:
            while len(got) < 4096:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                got += chunk
                if len(got) >= 5:
                    break
        except socket.timeout:
            return Result("timeout", connect_ms, (time.monotonic() - started) * 1000, got, note)
        except ConnectionResetError:
            return Result("rst", connect_ms, (time.monotonic() - started) * 1000, got, note)

        total = (time.monotonic() - started) * 1000
        if not segments:
            return Result("tcp-ok", connect_ms, total, got, note)
        if not got:
            return Result("eof", connect_ms, total, got, note)
        return Result("ok", connect_ms, total, got, note)
    except ConnectionResetError:
        return Result("rst", connect_ms, (time.monotonic() - started) * 1000, b"", note)
    except BrokenPipeError:
        return Result("rst", connect_ms, (time.monotonic() - started) * 1000, b"", "сломанная труба")
    except OSError as exc:
        return Result("err", connect_ms, (time.monotonic() - started) * 1000, b"", str(exc))
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --- Режимы запуска --------------------------------------------------------


def run_matrix(
    targets: list[tuple[str, str]],
    ports: list[int],
    cases: list[str],
    repeat: int,
    read_timeout: float = READ_TIMEOUT,
) -> None:
    for label, ip in targets:
        for port in ports:
            print(f"\n=== {label} {ip}:{port} ===")
            for case in cases:
                segments, human = build_payload(case)
                human += f" [{sum(len(s) for s in segments)}б]"
                verdicts = []
                last = None
                for _ in range(repeat):
                    last = probe(ip, port, case, read_timeout=read_timeout)
                    verdicts.append(last.verdict)
                mix = ",".join(sorted(set(verdicts))) if len(set(verdicts)) > 1 else verdicts[0]
                counts = f" ({'/'.join(verdicts)})" if len(set(verdicts)) > 1 else ""
                print(f"  {case:28} {mix:10}{counts}  {last.describe()}   — {human}")


def run_ttl_scan(ip: str, port: int, case: str, max_ttl: int, repeat: int) -> None:
    print(f"=== сканирование по TTL: {ip}:{port}, проба {case} ===")
    print("   TTL  вердикт     подробности")
    marker = b"NETPROBE-MARKER-" + os.urandom(4).hex().encode()
    for ttl in range(1, max_ttl + 1):
        verdicts = []
        last = None
        for _ in range(repeat):
            last = probe(ip, port, case, ttl=ttl, marker=marker)
            verdicts.append(last.verdict)
        mix = "/".join(verdicts)
        print(f"  {ttl:4}  {mix:24} {last.describe()}")


def parse_target(text: str) -> tuple[str, str]:
    if "=" in text:
        label, _, ip = text.partition("=")
        return label, ip
    return text, text


def main() -> int:
    parser = argparse.ArgumentParser(description="Зонд фильтрации: что именно рвётся и где")
    parser.add_argument("targets", nargs="+", help="IP или метка=IP")
    parser.add_argument("--ports", default="443", help="порты через запятую")
    parser.add_argument("--cases", default=",".join(DEFAULT_CASES), help="пробы через запятую")
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--read-timeout", type=float, default=READ_TIMEOUT)
    parser.add_argument("--ttl-scan", metavar="CASE", help="сканировать TTL этой пробой")
    parser.add_argument("--max-ttl", type=int, default=20)
    args = parser.parse_args()

    targets = [parse_target(t) for t in args.targets]
    ports = [int(p) for p in args.ports.split(",")]

    if args.ttl_scan:
        for _, ip in targets:
            for port in ports:
                run_ttl_scan(ip, port, args.ttl_scan, args.max_ttl, args.repeat)
        return 0

    run_matrix(targets, ports, args.cases.split(","), args.repeat, args.read_timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
