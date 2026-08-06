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

#: Фоновый агент: чтобы прокси поднимался сам и переживал перезагрузку.
AGENT_LABEL = "com.vuutya.vpn-proxy"
AGENT_PLIST = os.path.expanduser(f"~/Library/LaunchAgents/{AGENT_LABEL}.plist")
AGENT_DIR = os.path.expanduser("~/Library/Application Support/vpnkit")
AGENT_CONFIG = os.path.join(AGENT_DIR, "proxy.json")
AGENT_LOG = os.path.expanduser("~/Library/Logs/vpnkit-proxy.log")


def plist_body(xray: str) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{xray}</string>
        <string>run</string>
        <string>-c</string>
        <string>{AGENT_CONFIG}</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{AGENT_LOG}</string>
    <key>StandardErrorPath</key><string>{AGENT_LOG}</string>
</dict>
</plist>
"""


def agent_loaded() -> bool:
    proc = subprocess.run(
        ["launchctl", "list", AGENT_LABEL], capture_output=True, text=True
    )
    return proc.returncode == 0


def unload_agent(quiet: bool = False) -> None:
    subprocess.run(
        ["launchctl", "bootout", f"gui/{os.getuid()}/{AGENT_LABEL}"],
        capture_output=True,
        text=True,
    )
    if not quiet:
        ok("агент выгружен")


def install_agent(route, socks_port: int, http_port: int, xray: str) -> None:
    """Ставит прокси фоновым сервисом: сам стартует и переживает перезагрузку."""
    os.makedirs(AGENT_DIR, exist_ok=True)
    with open(AGENT_CONFIG, "w", encoding="utf-8") as fh:
        json.dump(build_config(route.link, socks_port, http_port), fh, indent=1)
    os.chmod(AGENT_CONFIG, 0o600)

    os.makedirs(os.path.dirname(AGENT_PLIST), exist_ok=True)
    with open(AGENT_PLIST, "w", encoding="utf-8") as fh:
        fh.write(plist_body(xray))

    unload_agent(quiet=True)
    proc = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{os.getuid()}", AGENT_PLIST],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise VpnKitError(
            f"launchctl не принял агент: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    ok(f"агент установлен и запущен ({AGENT_LABEL})")
    print(f"    конфиг: {AGENT_CONFIG}")
    print(f"    лог:    {AGENT_LOG}")
    print("    снять:  python scripts/vpn_proxy.py --uninstall-agent")


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
    parser.add_argument(
        "--install-agent",
        action="store_true",
        help="поставить прокси фоновым сервисом: сам стартует и переживает перезагрузку",
    )
    parser.add_argument(
        "--uninstall-agent", action="store_true", help="снять фоновый сервис"
    )
    parser.add_argument("--status", action="store_true", help="показать состояние сервиса")
    args = parser.parse_args()

    if args.uninstall_agent:
        unload_agent()
        for path in (AGENT_PLIST, AGENT_CONFIG):
            if os.path.exists(path):
                os.unlink(path)
        ok("файлы агента удалены")
        return 0

    if args.status:
        print(f"агент {AGENT_LABEL}: {'запущен ✓' if agent_loaded() else 'не установлен'}")
        if os.path.exists(AGENT_CONFIG):
            print(f"конфиг: {AGENT_CONFIG}")
        return 0

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

        if args.install_agent:
            install_agent(route, args.socks_port, args.http_port, xray)
            print_usage_hints(args.socks_port, args.http_port, route.label)
            return 0

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
