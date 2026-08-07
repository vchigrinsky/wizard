#!/usr/bin/env python3
"""Маяк: сервер-приёмник для замеров в отрезанной сети.

Ставится заранее на узлы, откуда потом будут ждать ответа:

    python3 blackout_beacon.py                    # разово, в терминале
    sudo python3 blackout_beacon.py --install     # службой, переживает перезагрузку
    python3 blackout_beacon.py --report           # что прилетало

Зачем нужен именно приёмник
---------------------------

Зонд на ноутбуке видит только одно: пришёл ответ или не пришёл. Но «не
пришёл» — это два совершенно разных диагноза: пакет не вышел от нас, или
вышел, дошёл, а обратно не пустили. Различить их с одной стороны нельзя.

Маяк пишет в журнал всё, что до него долетело, с точным временем и адресом
отправителя. Поэтому даже если ответ не вернулся, запись в журнале доказывает,
что наш пакет ушёл и дошёл. Это ровно та половина картины, которой не хватает.

Что умеет
---------

Слушает много портов сразу — и TCP, и UDP, — потому что заранее неизвестно,
какие из них уцелеют. На всё отвечает опознавательным маркером, чтобы зонд
понимал: ответил именно маяк, а не заглушка провайдера.

Отдельно умеет отдавать поток нужного объёма по запросу ``BULK <байт>``. Это
нужно для проверки «отсечки»: в режиме белых списков соединение не рвут, а
глушат после первых 16–20 килобайт, и поймать это можно только попыткой
прокачать заметный объём.

Журнал — JSONL, по строке на событие, рядом со скриптом.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import socket
import socketserver
import sys
import threading

MARKER = b"BEACON-OK"
BULK_CHUNK = b"\x00" * 8192
MAX_BULK = 64 * 1024 * 1024

#: Порты подобраны так, чтобы не спорить с тем, что уже работает на узле
#: (443 занят Xray, 22 — SSH, 53 — резолвером), и при этом покрыть разные
#: «категории»: обычный веб, типичные альтернативы HTTPS, высокий порт.
DEFAULT_TCP = [80, 2053, 8080, 8443, 9443, 40000]
DEFAULT_UDP = [2053, 8443, 40000, 51820]

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "beacon-log.jsonl")
UNIT_NAME = "blackout-beacon"

_log_lock = threading.Lock()


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def record(event: dict) -> None:
    event["time"] = now()
    line = json.dumps(event, ensure_ascii=False)
    with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    print(line, flush=True)


def parse_bulk(data: bytes) -> int | None:
    """``BULK 1048576`` где-нибудь в первых байтах -> сколько отдать."""
    marker = data.find(b"BULK")
    if marker < 0:
        return None
    tail = data[marker + 4 : marker + 24].split(b"\n", 1)[0].strip()
    try:
        return min(int(tail), MAX_BULK)
    except ValueError:
        return 1024 * 1024


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        port = self.server.server_address[1]
        src = f"{self.client_address[0]}:{self.client_address[1]}"
        self.request.settimeout(20)
        try:
            data = self.request.recv(8192)
        except OSError:
            data = b""

        event = {
            "proto": "tcp", "port": port, "from": src,
            "bytes": len(data), "head": data[:24].hex(),
        }
        # Если прилетело приветствие TLS — вытаскиваем имя, это самое ценное:
        # видно, с каким SNI до нас реально дошли.
        sni = extract_sni(data)
        if sni:
            event["sni"] = sni

        want = parse_bulk(data)
        try:
            self.request.sendall(MARKER + b" port=%d\n" % port)
            if want:
                event["bulk_requested"] = want
                sent = 0
                while sent < want:
                    chunk = BULK_CHUNK[: min(len(BULK_CHUNK), want - sent)]
                    self.request.sendall(chunk)
                    sent += len(chunk)
                event["bulk_sent"] = sent
        except OSError as exc:
            event["send_error"] = str(exc)
        record(event)


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        port = self.server.server_address[1]
        record({"proto": "udp", "port": port,
                "from": f"{self.client_address[0]}:{self.client_address[1]}",
                "bytes": len(data), "head": data[:24].hex()})
        try:
            sock.sendto(MARKER + b" udp=%d\n" % port, self.client_address)
        except OSError:
            pass


def extract_sni(data: bytes) -> str | None:
    """Достаёт имя из ClientHello. Разбор минимальный и намеренно грубый:
    нам нужно опознать имя, а не проверить корректность рукопожатия."""
    if len(data) < 45 or data[0] != 0x16:
        return None
    try:
        pos = 43                                    # до session_id
        pos += 1 + data[pos]                        # session_id
        pos += 2 + int.from_bytes(data[pos:pos + 2], "big")      # cipher suites
        pos += 1 + data[pos]                        # compression
        pos += 2                                    # длина блока расширений
        while pos + 4 <= len(data):
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            body = data[pos + 4:pos + 4 + ext_len]
            if ext_type == 0 and len(body) >= 5:
                name_len = int.from_bytes(body[3:5], "big")
                return body[5:5 + name_len].decode("ascii", "replace")
            pos += 4 + ext_len
    except (IndexError, ValueError):
        return None
    return None


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(tcp_ports: list[int], udp_ports: list[int]) -> None:
    started_tcp, started_udp, failed = [], [], []
    for port in tcp_ports:
        try:
            server = ReusableTCPServer(("0.0.0.0", port), TcpHandler)
        except OSError as exc:
            failed.append(f"tcp/{port} ({exc.strerror or exc})")
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started_tcp.append(port)
    for port in udp_ports:
        try:
            server = ReusableUDPServer(("0.0.0.0", port), UdpHandler)
        except OSError as exc:
            failed.append(f"udp/{port} ({exc.strerror or exc})")
            continue
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started_udp.append(port)

    record({"event": "start", "tcp": started_tcp, "udp": started_udp, "skipped": failed})
    print(f"маяк слушает: tcp {started_tcp}, udp {started_udp}")
    if failed:
        print(f"занято или недоступно: {', '.join(failed)}")
    print(f"журнал: {LOG_PATH}")
    threading.Event().wait()


def install(tcp_ports: list[int], udp_ports: list[int]) -> None:
    """Ставит службой systemd: маяк должен пережить и разрыв, и перезагрузку."""
    script = os.path.abspath(__file__)
    unit = f"""[Unit]
Description=Blackout beacon
After=network.target

[Service]
ExecStart={sys.executable} {script} --tcp {','.join(map(str, tcp_ports))} --udp {','.join(map(str, udp_ports))}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"""
    path = f"/etc/systemd/system/{UNIT_NAME}.service"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(unit)
    os.system("systemctl daemon-reload")
    os.system(f"systemctl enable --now {UNIT_NAME}")
    print(f"служба {UNIT_NAME} установлена и запущена")
    print(f"смотреть: journalctl -u {UNIT_NAME} -f   или   {LOG_PATH}")


def report() -> None:
    if not os.path.exists(LOG_PATH):
        print(f"журнала ещё нет: {LOG_PATH}")
        return
    by_source: dict[str, list[dict]] = {}
    with open(LOG_PATH, encoding="utf-8") as fh:
        for line in fh:
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if "from" not in event:
                continue
            by_source.setdefault(event["from"].split(":")[0], []).append(event)

    print(f"адресов, с которых до маяка долетало: {len(by_source)}\n")
    for ip, events in sorted(by_source.items(), key=lambda kv: -len(kv[1])):
        ports = sorted({f"{e['proto']}/{e['port']}" for e in events})
        snis = sorted({e["sni"] for e in events if e.get("sni")})
        first, last = events[0]["time"], events[-1]["time"]
        print(f"  {ip:16} событий {len(events):4}   {first} .. {last}")
        print(f"      порты: {', '.join(ports)}")
        if snis:
            print(f"      имена: {', '.join(snis)}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Маяк для замеров в отрезанной сети")
    parser.add_argument("--tcp", default=",".join(map(str, DEFAULT_TCP)))
    parser.add_argument("--udp", default=",".join(map(str, DEFAULT_UDP)))
    parser.add_argument("--install", action="store_true", help="поставить службой systemd")
    parser.add_argument("--report", action="store_true", help="сводка по журналу")
    args = parser.parse_args()

    tcp_ports = [int(p) for p in args.tcp.split(",") if p]
    udp_ports = [int(p) for p in args.udp.split(",") if p]

    if args.report:
        report()
        return 0
    if args.install:
        if os.geteuid() != 0:
            print("нужен root", file=sys.stderr)
            return 2
        install(tcp_ports, udp_ports)
        return 0
    serve(tcp_ports, udp_ports)
    return 0


if __name__ == "__main__":
    sys.exit(main())
