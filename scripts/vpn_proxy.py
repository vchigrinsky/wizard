#!/usr/bin/env python3
"""Поднять локальный прокси поверх любого маршрута из vless.md.

    python scripts/vpn_proxy.py ПОДСТРОКА
    python scripts/vpn_proxy.py --list

Например::

    python scripts/vpn_proxy.py 'timeweb ← 🇷🇺 timeweb'
    python scripts/vpn_proxy.py bigvds --socks-port 1080 --http-port 1081

Скрипт запускает локальный ``xray``, который принимает обычные SOCKS5 и HTTP
и заворачивает их в ваш VLESS/REALITY-маршрут. На серверах при этом ничего
поднимать и менять не нужно: маршрут уже есть, не хватало только локальной
головы, которая переведёт привычный прокси-протокол в этот транспорт.

Держите процесс запущенным, пока пользуетесь прокси; остановка — Ctrl+C.

Почему не демон на сервере
--------------------------

Соблазнительно поставить на узел dante или 3proxy и ходить прямо на него. Так
делать не стоит: трафик от вас до сервера пойдёт открытым прокси-протоколом,
без маскировки под TLS, и ТСПУ опознает его сразу — то есть вы потеряете ровно
то, ради чего в схеме используется REALITY. Плюс получите открытый порт с
паролем, который начнут перебирать. Локальная голова оставляет канал до узла
неотличимым от обычного TLS.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_check_routes import find_xray, outbound_from_link, parse_vless_file  # noqa: E402
from vpnkit import VpnKitError, fail, ok, step  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_VLESS_FILE = os.path.join(REPO_ROOT, "vless.md")

DEFAULT_SOCKS_PORT = 1080
DEFAULT_HTTP_PORT = 1081


def build_config(link: str, socks_port: int, http_port: int) -> dict:
    """SOCKS5 и HTTP внутрь, VLESS/REALITY наружу.

    Два инбаунда, а не один, потому что переменные ``HTTP_PROXY``/``HTTPS_PROXY``
    понимают далеко не все клиенты в варианте с SOCKS: curl и git — да, а,
    например, requests в Python без отдельной зависимости — нет. HTTP-инбаунд
    принимает и обычные запросы, и CONNECT для HTTPS, поэтому годится всем.
    """
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": http_port,
                "protocol": "http",
                "settings": {},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
        ],
        "outbounds": [outbound_from_link(link), {"tag": "direct", "protocol": "freedom"}],
    }


def print_usage_hints(socks_port: int, http_port: int, label: str) -> None:
    print()
    print(f"  Маршрут:  {label}")
    print(f"  SOCKS5:   127.0.0.1:{socks_port}")
    print(f"  HTTP:     127.0.0.1:{http_port}")
    print()
    print("  Переменные окружения (для текущего терминала):")
    print(f"    export HTTP_PROXY=http://127.0.0.1:{http_port}")
    print(f"    export HTTPS_PROXY=http://127.0.0.1:{http_port}")
    print("    export NO_PROXY=localhost,127.0.0.1,::1")
    print()
    print("  ZeroOmega: профиль типа Proxy, протокол SOCKS5,")
    print(f"             сервер 127.0.0.1, порт {socks_port}")
    print()
    print("  Системный прокси macOS (нужен пароль администратора):")
    print(f'    networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 {http_port}')
    print(f'    networksetup -setwebproxy "Wi-Fi" 127.0.0.1 {http_port}')
    print('    выключить: networksetup -setsecurewebproxystate "Wi-Fi" off')
    print()
    print("  Проверка в соседнем терминале:")
    print(f"    curl -x http://127.0.0.1:{http_port} https://api.myip.com")
    print()
    print("  Ctrl+C — остановить.")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Локальный SOCKS5/HTTP-прокси поверх маршрута из vless.md",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "route", nargs="?", help="подстрока названия маршрута, например 'bigvds ← 🇷🇺 timeweb'"
    )
    parser.add_argument("--list", action="store_true", help="показать доступные маршруты")
    parser.add_argument("--vless-file", default=DEFAULT_VLESS_FILE, help="путь к vless.md")
    parser.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT)
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    args = parser.parse_args()

    config_path = None
    process = None
    try:
        xray = find_xray()
        path = os.path.abspath(args.vless_file)
        if not os.path.exists(path):
            raise VpnKitError(f"файл не найден: {path}")
        _, routes = parse_vless_file(path)

        if args.list or not args.route:
            print("Доступные маршруты:\n")
            for route in routes:
                mark = f" {route.mark}" if route.mark else ""
                print(f"  {route.label}{mark}")
            print("\nЗапуск: python scripts/vpn_proxy.py 'часть названия'")
            return 0

        needle = args.route.lower()
        found = [r for r in routes if needle in r.label.lower()]
        if not found:
            raise VpnKitError(
                f"под {args.route!r} не нашлось маршрутов; посмотрите список: --list"
            )
        if len(found) > 1:
            listing = "\n  ".join(r.label for r in found)
            raise VpnKitError(f"под {args.route!r} подходит несколько маршрутов:\n  {listing}")

        route = found[0]
        if route.mark == "❌":
            step(f"внимание: маршрут помечен ❌ — {route.label}")

        handle, config_path = tempfile.mkstemp(suffix=".json", prefix="vpnproxy-")
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(build_config(route.link, args.socks_port, args.http_port), fh)

        process = subprocess.Popen(
            [xray, "run", "-c", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        if process.poll() is not None:
            output = (process.stdout.read() if process.stdout else "") or ""
            raise VpnKitError(f"xray не запустился: {output.strip()[:400]}")

        ok("прокси поднят")
        print_usage_hints(args.socks_port, args.http_port, route.label)

        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        process.wait()
        return 0
    except VpnKitError as exc:
        fail(str(exc))
        return 1
    except (KeyboardInterrupt, SystemExit):
        print()
        ok("прокси остановлен")
        return 0
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)


if __name__ == "__main__":
    sys.exit(main())
