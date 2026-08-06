#!/usr/bin/env python3
"""Перепись фильтра: что режется, стабильно ли это и от чего зависит.

Запускать на узле, с которого наблюдается блокировка:

    python3 filter_census.py bigvds=109.104.153.242 timeweb=185.11.134.248 \
        --snis www.google.com,vk.com,example.com --cycles 3 --delay 5

    python3 filter_census.py bigvds=109.104.153.242 --rate www.google.com \
        --burst 8 --parallel

Зачем отдельный инструмент
--------------------------

Одиночная матрица проб отвечает на вопрос «режется ли имя X сейчас», но не
отличает три совершенно разные причины одного и того же наблюдения:

1. **список имён** — фильтр знает набор доменов и режет именно их;
2. **частота** — фильтр считает рукопожатия к одному адресу и глушит лишние,
   а какое там имя, неважно; тогда «заблокированным» окажется то имя, которое
   не повезло оказаться четвёртым подряд;
3. **случайность** — часть пакетов теряется, и всё это просто шум.

Различить их можно только измерением: гонять одни и те же имена несколько
раз, вперемешку, с паузами, и смотреть на воспроизводимость.

Режим переписи (по умолчанию) прогоняет каждое имя по одному разу за цикл,
порядок при желании перемешивается, между пробами держится пауза. Если
результат по имени повторяется из цикла в цикл независимо от его места в
очереди — это список имён. Если «плохими» оказываются разные имена и всегда
примерно столько же — это частота. Если картина не повторяется вовсе — шум.

Режим ``--rate`` бьёт в одну точку: открывает пачку соединений с одним и тем
же именем и показывает, начиная с какого по счёту рукопожатия начинаются
потери. Это прямая проверка гипотезы про частоту.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import os
import random
import socket
import ssl
import sys
import time

CONNECT_TIMEOUT = 6.0


def client_hello(sni: str) -> bytes:
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


def handshake(ip: str, port: int, payload: bytes, read_timeout: float) -> tuple[str, float]:
    """Возвращает (вердикт, миллисекунды). Вердикт: ok / drop / rst / eof / no-tcp."""
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(CONNECT_TIMEOUT)
    try:
        sock.connect((ip, port))
    except OSError:
        return "no-tcp", (time.monotonic() - started) * 1000
    try:
        sock.sendall(payload)
        sock.settimeout(read_timeout)
        data = sock.recv(4096)
        elapsed = (time.monotonic() - started) * 1000
        if not data:
            return "eof", elapsed
        return "ok", elapsed
    except socket.timeout:
        return "drop", (time.monotonic() - started) * 1000
    except ConnectionResetError:
        return "rst", (time.monotonic() - started) * 1000
    except OSError:
        return "err", (time.monotonic() - started) * 1000
    finally:
        sock.close()


MARK = {"ok": "·", "drop": "X", "rst": "R", "eof": "e", "no-tcp": "?", "err": "!"}


def now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def run_census(targets, port, snis, cycles, delay, shuffle, read_timeout) -> None:
    payloads = {sni: client_hello(sni) for sni in snis}
    # результат[(метка, имя)] = список вердиктов по циклам
    result: dict[tuple[str, str], list[str]] = {}
    print(f"перепись: {len(targets)} адрес(ов) × {len(snis)} имён × {cycles} циклов, "
          f"пауза {delay} с, порядок {'перемешан' if shuffle else 'фиксирован'}\n")

    for cycle in range(1, cycles + 1):
        order = list(snis)
        if shuffle:
            random.shuffle(order)
        print(f"--- цикл {cycle} ({now()})")
        for sni in order:
            for label, ip in targets:
                verdict, ms = handshake(ip, port, payloads[sni], read_timeout)
                result.setdefault((label, sni), []).append(verdict)
                print(f"    {now()}  {label:10} {sni:26} {verdict:6} {ms:6.0f}мс")
                if delay:
                    time.sleep(delay)

    print("\n=== сводка (· прошло, X съедено, R сброшено) ===")
    width = max(len(s) for s in snis) + 2
    for label, _ in targets:
        print(f"\n  {label}")
        for sni in snis:
            marks = "".join(MARK.get(v, "?") for v in result.get((label, sni), []))
            bad = sum(1 for v in result.get((label, sni), []) if v != "ok")
            verdict = "стабильно режется" if bad == cycles else (
                "стабильно проходит" if bad == 0 else "плавает")
            print(f"    {sni.ljust(width)} {marks:10}  {verdict}")


def run_rate(targets, port, sni, burst, parallel, gap, read_timeout, rounds, pause) -> None:
    payload = client_hello(sni)
    print(f"проверка частоты: SNI={sni}, пачка по {burst} соединений, "
          f"{'параллельно' if parallel else f'подряд с паузой {gap} с'}, "
          f"раундов {rounds}, между раундами {pause} с\n")

    for rnd in range(1, rounds + 1):
        started = time.monotonic()
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(max_workers=burst) as pool:
                futures = [
                    pool.submit(handshake, ip, port, payload, read_timeout)
                    for _, ip in targets
                    for _ in range(burst)
                ]
                outcomes = [f.result() for f in futures]
        else:
            outcomes = []
            for _, ip in targets:
                for i in range(burst):
                    if i and gap:
                        time.sleep(gap)
                    outcomes.append(handshake(ip, port, payload, read_timeout))

        marks = "".join(MARK.get(v, "?") for v, _ in outcomes)
        good = sum(1 for v, _ in outcomes if v == "ok")
        elapsed = time.monotonic() - started
        print(f"  раунд {rnd} ({now()}): {marks}   прошло {good}/{len(outcomes)}, "
              f"{elapsed:.1f} с")
        if rnd < rounds and pause:
            time.sleep(pause)


def fresh_sni(tag: str, n: int) -> str:
    """Имя, которого фильтр раньше не видел.

    Нужно именно свежее: если брать уже засвеченное, невозможно отличить
    «сработало сейчас» от «оставалось замороженным с прошлого раза».
    """
    return f"n{n}-{tag}.example.net"


def run_freeze(targets, port, burst, interval, max_wait, read_timeout) -> None:
    """Проверяет: пачка параллельных рукопожатий морозит имя — и надолго ли.

    Берём два ни разу не использованных имени. Убеждаемся, что оба проходят.
    Бьём пачкой только по первому. Дальше опрашиваем оба: если первое легло, а
    второе живо — заморозка адресная, по имени. Время до возврата первого и
    есть длительность наказания.
    """
    tag = os.urandom(3).hex()
    hot, cold = fresh_sni(tag, 1), fresh_sni(tag, 2)
    payload_hot, payload_cold = client_hello(hot), client_hello(cold)

    for label, ip in targets:
        print(f"\n=== {label} {ip}:{port} ===")
        print(f"    обстреливаемое имя: {hot}")
        print(f"    контрольное имя:    {cold}")

        v_hot, _ = handshake(ip, port, payload_hot, read_timeout)
        v_cold, _ = handshake(ip, port, payload_cold, read_timeout)
        print(f"  {now()} до обстрела:  {hot} → {v_hot},  {cold} → {v_cold}")
        if v_hot != "ok":
            print("  оба имени должны сначала проходить — иначе опыт бессмысленен")
            continue

        print(f"  {now()} пачка: {burst} параллельных рукопожатий по {hot}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=burst) as pool:
            futures = [
                pool.submit(handshake, ip, port, payload_hot, read_timeout)
                for _ in range(burst)
            ]
            outcomes = [f.result() for f in futures]
        marks = "".join(MARK.get(v, "?") for v, _ in outcomes)
        good = sum(1 for v, _ in outcomes if v == "ok")
        print(f"  {now()} итог пачки: {marks}  прошло {good}/{burst}")

        started = time.monotonic()
        recovered = None
        while time.monotonic() - started < max_wait:
            v_hot, _ = handshake(ip, port, payload_hot, read_timeout)
            v_cold, _ = handshake(ip, port, payload_cold, read_timeout)
            waited = time.monotonic() - started
            print(f"  {now()} +{waited:5.0f}с   {hot} → {v_hot:6}   {cold} → {v_cold}")
            if v_hot == "ok":
                recovered = waited
                break
            time.sleep(interval)

        if recovered is None:
            print(f"  за {max_wait:.0f} с имя так и не отмёрзло")
        else:
            print(f"  имя отмёрзло через {recovered:.0f} с после обстрела")


def run_ramp(targets, port, sizes, read_timeout, cooldown) -> None:
    """Ищет порог: со скольки параллельных рукопожатий начинается наказание.

    Каждый размер пачки проверяется своим свежим именем, иначе предыдущая
    заморозка потянется в следующий замер и порог уедет вниз.
    """
    tag = os.urandom(3).hex()
    for label, ip in targets:
        print(f"\n=== {label} {ip}:{port} ===")
        for i, size in enumerate(sizes):
            sni = fresh_sni(f"{tag}r{size}", i)
            payload = client_hello(sni)
            with concurrent.futures.ThreadPoolExecutor(max_workers=size) as pool:
                outcomes = [f.result() for f in [
                    pool.submit(handshake, ip, port, payload, read_timeout)
                    for _ in range(size)
                ]]
            marks = "".join(MARK.get(v, "?") for v, _ in outcomes)
            good = sum(1 for v, _ in outcomes if v == "ok")
            after, _ = handshake(ip, port, payload, read_timeout)
            print(f"  {now()} пачка {size:2}: {marks:12} прошло {good}/{size};"
                  f" следом одиночная проба → {after}")
            time.sleep(cooldown)


def parse_target(text: str) -> tuple[str, str]:
    if "=" in text:
        label, _, ip = text.partition("=")
        return label, ip
    return text, text


def main() -> int:
    parser = argparse.ArgumentParser(description="Перепись фильтра: имя, частота или шум")
    parser.add_argument("targets", nargs="+", help="IP или метка=IP")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--snis", default="www.google.com,vk.com,example.com")
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--delay", type=float, default=3.0, help="пауза между пробами, с")
    parser.add_argument("--shuffle", action="store_true", help="мешать порядок имён")
    parser.add_argument("--read-timeout", type=float, default=4.0)
    parser.add_argument("--rate", metavar="SNI", help="режим проверки частоты по этому имени")
    parser.add_argument("--burst", type=int, default=8)
    parser.add_argument("--parallel", action="store_true")
    parser.add_argument("--gap", type=float, default=0.0, help="пауза внутри пачки, с")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--pause", type=float, default=20.0, help="пауза между раундами, с")
    parser.add_argument("--freeze", action="store_true",
                        help="опыт на заморозку: пачка по свежему имени и время возврата")
    parser.add_argument("--interval", type=float, default=10.0, help="шаг опроса при --freeze, с")
    parser.add_argument("--max-wait", type=float, default=420.0, help="сколько ждать оттаивания, с")
    parser.add_argument("--ramp", metavar="SIZES", help="искать порог: размеры пачек через запятую")
    parser.add_argument("--cooldown", type=float, default=30.0, help="пауза между пачками --ramp, с")
    args = parser.parse_args()

    targets = [parse_target(t) for t in args.targets]
    if args.freeze:
        run_freeze(targets, args.port, args.burst, args.interval, args.max_wait,
                   args.read_timeout)
    elif args.ramp:
        run_ramp(targets, args.port, [int(s) for s in args.ramp.split(",")],
                 args.read_timeout, args.cooldown)
    elif args.rate:
        run_rate(targets, args.port, args.rate, args.burst, args.parallel,
                 args.gap, args.read_timeout, args.rounds, args.pause)
    else:
        run_census(targets, args.port, [s for s in args.snis.split(",") if s],
                   args.cycles, args.delay, args.shuffle, args.read_timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
