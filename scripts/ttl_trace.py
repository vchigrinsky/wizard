#!/usr/bin/env python3
"""Определение хопа, на котором фильтр съедает пакет.

Запускать на том узле, откуда наблюдается блокировка, из-под root:

    sudo python3 ttl_trace.py 109.104.153.242 --blocked www.google.com --allowed example.com

Метод
-----

Обычный traceroute находит маршрут, но ничего не говорит о том, где стоит
фильтр: фильтр не отвечает и в трассировке не виден. Здесь используется то,
что фильтр *съедает конкретный пакет*, и это можно превратить в измерение.

Отправляем TLS-приветствие с искусственно заниженным TTL, равным k:

* если k меньше расстояния до фильтра — пакет умирает на k-м маршрутизаторе,
  и тот честно присылает ICMP «время жизни истекло». Фильтр пакета не видел;
* если k больше либо равно расстоянию до фильтра — пакет сначала доходит до
  фильтра, тот его выбрасывает, и до k-го маршрутизатора пакет уже не
  добирается. ICMP не приходит.

Значит наименьшее k, при котором ICMP пропал, и есть число хопов до фильтра.

Чтобы знать, какой маршрутизатор стоит на каждом хопе (в том числе за
фильтром), тот же перебор делается вторым, безобидным именем — оно проходит
насквозь и даёт полную карту пути. Разница двух колонок и показывает точку.

ICMP принимаем сырым сокетом, а не парсингом tcpdump: в теле ICMP лежит
начало исходного пакета, оттуда берём номер порта отправителя и по нему
точно понимаем, на какую именно пробу пришёл ответ.
"""

from __future__ import annotations

import argparse
import os
import select
import socket
import ssl
import struct
import sys
import time

ICMP_TIME_EXCEEDED = 11
ICMP_DEST_UNREACH = 3


def client_hello(sni: str) -> bytes:
    """Короткое приветствие TLS 1.2 — влезает в один сегмент."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLError:
        pass
    return outgoing.read()


class IcmpListener:
    """Сырой сокет ICMP: слушает ответы «время жизни истекло»."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.setblocking(False)
        #: порт отправителя пробы -> (IP маршрутизатора, тип ICMP)
        self.seen: dict[int, tuple[str, int]] = {}

    def drain(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            ready, _, _ = select.select([self.sock], [], [], left)
            if not ready:
                return
            try:
                data, _ = self.sock.recvfrom(2048)
            except OSError:
                return
            self._parse(data)

    def _parse(self, data: bytes) -> None:
        if len(data) < 28:
            return
        outer_ihl = (data[0] & 0x0F) * 4
        icmp = data[outer_ihl:]
        if len(icmp) < 8:
            return
        icmp_type = icmp[0]
        if icmp_type not in (ICMP_TIME_EXCEEDED, ICMP_DEST_UNREACH):
            return
        router = socket.inet_ntoa(data[12:16])

        inner = icmp[8:]
        if len(inner) < 20:
            return
        inner_ihl = (inner[0] & 0x0F) * 4
        tcp = inner[inner_ihl:]
        if len(tcp) < 4:
            return
        sport = struct.unpack("!H", tcp[0:2])[0]
        self.seen.setdefault(sport, (router, icmp_type))


def probe_with_ttl(ip: str, port: int, payload: bytes, ttl: int, listener: IcmpListener,
                   settle: float) -> int | None:
    """Шлёт приветствие с заданным TTL. Возвращает порт отправителя."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(6)
    try:
        sock.connect((ip, port))
    except OSError:
        return None
    sport = sock.getsockname()[1]
    try:
        # TTL занижаем уже после рукопожатия: сами SYN/ACK должны дойти,
        # иначе соединение не встанет и приветствие некуда будет слать.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        sock.sendall(payload)
        listener.drain(settle)
    except OSError:
        pass
    finally:
        try:
            # Закрываем через RST: не хочется оставлять за собой хвост из
            # полуоткрытых соединений, их и так за прогон набирается много.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                            struct.pack("ii", 1, 0))
        except OSError:
            pass
        sock.close()
    return sport


def run(ip: str, port: int, blocked: str, allowed: str, max_ttl: int, settle: float) -> None:
    names = [("режется", blocked), ("проходит", allowed)]
    payloads = {label: client_hello(sni) for label, sni in names}

    print(f"цель: {ip}:{port}")
    for label, sni in names:
        print(f"  проба «{label}»: SNI={sni}, {len(payloads[label])} байт")
    print()

    rows: dict[int, dict[str, str]] = {}
    for ttl in range(1, max_ttl + 1):
        rows[ttl] = {}
        for label, _ in names:
            listener = IcmpListener()
            sport = probe_with_ttl(ip, port, payloads[label], ttl, listener, settle)
            if sport is None:
                rows[ttl][label] = "нет TCP"
                continue
            listener.drain(0.4)
            hit = listener.seen.get(sport)
            rows[ttl][label] = hit[0] if hit else "—"

    width = max(len(label) for label, _ in names) + 2
    print(f"  TTL  {'режется'.ljust(width)} {'проходит'.ljust(width)}  что это значит")
    first_gap = None
    for ttl in range(1, max_ttl + 1):
        b = rows[ttl]["режется"]
        a = rows[ttl]["проходит"]
        note = ""
        if a != "—" and b == "—" and first_gap is None:
            first_gap = ttl
            note = "<<< здесь пакет уже съеден"
        elif a == "—" and b == "—":
            note = "дальше конечного узла"
        print(f"  {ttl:4}  {b.ljust(width)} {a.ljust(width)}  {note}")

    print()
    if first_gap:
        print(f"фильтр стоит на {first_gap}-м хопе от нас: пакет с плохим именем "
              f"до этого маршрутизатора уже не доходит, а с хорошим — доходит")
    else:
        print("расхождения нет: локализовать по TTL не удалось")


def main() -> int:
    parser = argparse.ArgumentParser(description="Где именно съедается пакет")
    parser.add_argument("ip")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--blocked", default="www.google.com", help="SNI, который режется")
    parser.add_argument("--allowed", default="example.com", help="SNI, который проходит")
    parser.add_argument("--max-ttl", type=int, default=12)
    parser.add_argument("--settle", type=float, default=0.8, help="сколько ждать ICMP, секунд")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("нужен root: сырой ICMP-сокет иначе не открыть", file=sys.stderr)
        return 2
    run(args.ip, args.port, args.blocked, args.allowed, args.max_ttl, args.settle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
