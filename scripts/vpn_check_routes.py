#!/usr/bin/env python3
"""Шаг 2: прогнать все маршруты из vless.md и разметить рабочие.

    python scripts/vpn_check_routes.py /path/to/vless.md

Скрипт берёт каждый маршрут, поднимает на него локальный туннель, смотрит, в
какой стране оказался выход, и дописывает к заголовку ✅ или ❌. Уже
размеченные маршруты пропускаются, так что повторный запуск проверяет только
новое — а чтобы перепроверить всё заново, есть ``--recheck``.

Как именно проверяется
----------------------

Вместо v2RayTun поднимается локальный ``xray`` с SOCKS-прокси на 127.0.0.1.
Так сделано по двум причинам. Во-первых, у v2RayTun на macOS нет ни CLI, ни
AppleScript-словаря — есть только URL-схема ``v2raytun://`` на импорт, то есть
включать и выключать туннель программно нечем, пришлось бы кликать по
интерфейсу. Во-вторых, системный VPN уводит в туннель весь трафик машины
целиком, включая эту самую проверку и всё остальное, что у вас открыто;
SOCKS-прокси же трогает ровно те запросы, которые мы через него сами пустили.
Маршрут при этом проверяется тот же самый и теми же протоколами.

Критерии
--------

Галочка ставится, только если прошли обе проверки.

**Страна.** Выход через туннель должен оказаться в стране зарубежного узла из
названия маршрута. Опрашивается несколько гео-сервисов, потому что их базы
расходятся между собой — засчитывается совпадение хотя бы по одному.

**Нагрузка.** По маршруту прогоняется заметный объём в несколько параллельных
соединений — так, как его нагрузил бы обычный браузер. Одной проверки страны
мало: ТСПУ спокойно пропускают короткий запрос на пару килобайт, а душат уже
поток, поэтому маршрут отвечает на гео-запрос и при этом непригоден для
реального пользования. Проба валит маршрут, если соединение оборвалось,
докачалось не всё или средняя скорость ушла ниже порога.

Объём, число потоков, таймаут и порог скорости настраиваются флагами —
значения по умолчанию подобраны так, чтобы отсечь задушенные маршруты, не
браковав просто небыстрые.

Требуется установленный ``xray`` (``brew install xray``).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpnkit import (  # noqa: E402
    STATUS_MARKS,
    VpnKitError,
    country_from_flag,
    env_without_proxy,
    fail,
    ok,
    sort_route_file,
    step,
    warn,
)

MARK_OK, MARK_BAD = STATUS_MARKS
MARKS = STATUS_MARKS

#: Гео-сервисы для проверки через туннель. Базы у них расходятся, поэтому
#: спрашиваем несколько и засчитываем совпадение по любому.
GEO_PROVIDERS = [
    ("api.myip.com", "https://api.myip.com", ("cc",)),
    ("2ip.ua", "https://api.2ip.ua/geo.json", ("country_code",)),
    ("ipwho.is", "https://ipwho.is/", ("country_code",)),
    ("ifconfig.co", "https://ifconfig.co/json", ("country_iso",)),
]

CURL_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122 Safari/537.36"

#: Откуда качаем нагрузочный трафик. Размер задаётся прямо в URL, так что
#: одна и та же ручка годится под любой объём.
TRAFFIC_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"

#: Значения по умолчанию для нагрузочной пробы. Все три меняются флагами.
TRAFFIC_MB = 32          # сколько мегабайт тянуть суммарно
TRAFFIC_STREAMS = 4      # в сколько параллельных соединений
TRAFFIC_TIMEOUT = 45     # секунд на одно соединение
MIN_SPEED_MBIT = 2.0     # ниже этой средней скорости маршрут считаем негодным

#: Сколько процентов заказанного объёма должно реально дойти.
TRAFFIC_COMPLETENESS = 0.95


# --- Разбор vless.md -------------------------------------------------------


class Route:
    def __init__(self, header_index: int, label: str, mark: str | None, link: str, link_index: int):
        self.header_index = header_index
        self.label = label
        self.mark = mark
        self.link = link
        self.link_index = link_index
        self.expected_country = country_from_flag(label)

    def __repr__(self) -> str:  # для отладочного вывода
        return f"<Route {self.label!r} {self.expected_country}>"


def parse_vless_file(path: str) -> tuple[list[str], list[Route]]:
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    routes: list[Route] = []
    for i, line in enumerate(lines):
        if not line.startswith("## "):
            continue
        raw = line[3:].strip()
        mark = next((m for m in MARKS if m in raw), None)
        label = raw
        for m in MARKS:
            label = label.replace(m, "")
        label = label.strip()

        link, link_index = None, None
        for j in range(i + 1, len(lines)):
            if lines[j].startswith("## "):
                break
            if lines[j].strip().startswith("vless://"):
                link, link_index = lines[j].strip(), j
                break
        if link:
            routes.append(Route(i, label, mark, link, link_index))
    return lines, routes


def apply_mark(lines: list[str], route: Route, mark: str) -> None:
    lines[route.header_index] = f"## {route.label} {mark}"


# --- Локальный xray --------------------------------------------------------


def detect_system_tunnel() -> str | None:
    """Ищет системный VPN, через который уходит весь трафик машины.

    Если поднят v2RayTun (или любой другой клиент в режиме TUN), маршрут по
    умолчанию смотрит в utun-интерфейс. Тогда исходящие соединения нашего
    локального xray к российским узлам заворачиваются сначала в чужой туннель,
    REALITY-хендшейк внутри него разваливается, и проверка браковала бы
    подряд все маршруты, включая исправные.
    """
    try:
        proc = subprocess.run(
            ["route", "-n", "get", "default"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    interface = None
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
    if not interface or not interface.startswith("utun"):
        return None

    address = ""
    try:
        info = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, timeout=10
        )
        for line in info.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == "inet":
                address = parts[1]
                break
    except (OSError, subprocess.TimeoutExpired):
        pass
    return f"{interface}{f' ({address})' if address else ''}"


def find_xray() -> str:
    path = shutil.which("xray")
    if not path:
        raise VpnKitError(
            "не найден xray — поставьте его: brew install xray "
            "(он нужен, чтобы поднять туннель для проверки)"
        )
    return path


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def outbound_from_link(link: str) -> dict:
    """Собирает outbound Xray из vless-ссылки."""
    parsed = urllib.parse.urlsplit(link)
    query = urllib.parse.parse_qs(parsed.query)
    one = lambda key, default="": query.get(key, [default])[0]  # noqa: E731

    if parsed.scheme != "vless":
        raise VpnKitError(f"поддерживается только vless://, а тут {parsed.scheme}://")

    stream: dict = {
        "network": one("type", "tcp"),
        "security": one("security", "reality"),
    }
    if stream["network"] == "tcp":
        stream["tcpSettings"] = {"header": {"type": "none"}}
    if stream["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": one("sni"),
            "fingerprint": one("fp", "firefox"),
            "publicKey": one("pbk"),
            "shortId": one("sid"),
            "spiderX": one("spx"),
        }
    elif stream["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": one("sni"),
            "fingerprint": one("fp", "firefox"),
        }

    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": parsed.port or 443,
                    "users": [
                        {
                            "id": urllib.parse.unquote(parsed.username or ""),
                            "encryption": one("encryption", "none"),
                            "flow": one("flow"),
                            "level": 0,
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }


def build_xray_config(link: str, port: int) -> dict:
    """Минимальный конфиг: SOCKS внутрь, маршрут наружу.

    Правил маршрутизации нет намеренно — всё, что мы сами пустим в этот
    прокси, уходит в туннель. Прямой трафик машины он не трогает.
    """
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            }
        ],
        "outbounds": [outbound_from_link(link), {"tag": "direct", "protocol": "freedom"}],
    }


class LocalTunnel:
    """Поднимает xray на время проверки одного маршрута."""

    def __init__(self, xray: str, link: str):
        self.xray = xray
        self.link = link
        self.port = free_port()
        self.proc: subprocess.Popen | None = None
        self._config_path: str | None = None

    def __enter__(self) -> "LocalTunnel":
        config = build_xray_config(self.link, self.port)
        handle, self._config_path = tempfile.mkstemp(suffix=".json", prefix="vpncheck-")
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            json.dump(config, fh)

        self.proc = subprocess.Popen(
            [self.xray, "run", "-c", self._config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                output = (self.proc.stdout.read() if self.proc.stdout else "") or ""
                raise VpnKitError(f"xray не запустился: {output.strip()[:400]}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.2)
        raise VpnKitError("xray не открыл SOCKS-порт за 15 секунд")

    def __exit__(self, *exc) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._config_path and os.path.exists(self._config_path):
            os.unlink(self._config_path)


# --- Гео-проверки ----------------------------------------------------------


def http_get(url: str, proxy_port: int, timeout: int = 20) -> str | None:
    proc = subprocess.run(
        [
            "curl", "-sS",
            "--socks5-hostname", f"127.0.0.1:{proxy_port}",
            "--max-time", str(timeout),
            "-A", CURL_UA,
            url,
        ],
        capture_output=True,
        text=True,
        env=env_without_proxy(),
    )
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return proc.stdout


def extract_country(body: str, keys: tuple[str, ...]) -> str | None:
    """Достаёт двухбуквенный код страны из JSON-ответа гео-сервиса."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and len(value) == 2:
            return value.lower()
    return None


def probe(providers, proxy_port: int) -> list[tuple[str, str | None]]:
    results = []
    for name, url, keys in providers:
        body = http_get(url, proxy_port=proxy_port)
        results.append((name, extract_country(body, keys) if body else None))
    return results


# --- Нагрузочная проба -----------------------------------------------------


def download_stream(proxy_port: int, size_bytes: int, timeout: int) -> dict:
    """Тянет через туннель один поток и возвращает, сколько реально дошло."""
    proc = subprocess.run(
        [
            "curl", "-sS", "-o", "/dev/null",
            "--socks5-hostname", f"127.0.0.1:{proxy_port}",
            "--max-time", str(timeout),
            "-A", CURL_UA,
            "-w", "%{size_download} %{http_code}",
            TRAFFIC_URL.format(bytes=size_bytes),
        ],
        capture_output=True,
        text=True,
        env=env_without_proxy(),
    )
    downloaded, status = 0, 0
    if proc.stdout.strip():
        parts = proc.stdout.strip().split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            downloaded, status = int(parts[0]), int(parts[1])
    return {
        "bytes": downloaded,
        "status": status,
        "curl_code": proc.returncode,
        "ok": proc.returncode == 0 and status == 200,
        "error": proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else "",
    }


def traffic_test(
    proxy_port: int,
    total_mb: int,
    streams: int,
    timeout: int,
    min_speed_mbit: float,
) -> tuple[bool, str]:
    """Гонит по маршруту заметный объём в несколько параллельных потоков.

    Проверка страны говорит только о том, что соединение вообще установилось:
    ТСПУ спокойно пропускают короткий запрос на пару килобайт, а душат уже
    поток. Поэтому маршрут дополнительно нагружается так, как его нагрузил бы
    обычный браузер — несколькими соединениями и десятками мегабайт подряд.
    """
    per_stream = max(1, total_mb * 1024 * 1024 // streams)
    expected = per_stream * streams

    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=streams) as pool:
        results = list(
            pool.map(
                lambda _: download_stream(proxy_port, per_stream, timeout),
                range(streams),
            )
        )
    elapsed = max(time.monotonic() - started, 1e-6)

    downloaded = sum(r["bytes"] for r in results)
    speed_mbit = downloaded * 8 / elapsed / 1_000_000
    broken = [r for r in results if not r["ok"]]

    got_mb = downloaded / 1024 / 1024
    want_mb = expected / 1024 / 1024
    summary = (
        f"{got_mb:.1f} из {want_mb:.0f} МБ за {elapsed:.1f} с, "
        f"{speed_mbit:.1f} Мбит/с в {streams} потока"
    )

    if broken:
        codes = ", ".join(
            f"curl {r['curl_code']}" if r["curl_code"] else f"HTTP {r['status']}"
            for r in broken
        )
        return False, f"поток оборвался ({len(broken)} из {streams}: {codes}); {summary}"
    if downloaded < expected * TRAFFIC_COMPLETENESS:
        return False, f"докачалось не всё; {summary}"
    if speed_mbit < min_speed_mbit:
        return False, f"скорость ниже порога {min_speed_mbit:g} Мбит/с; {summary}"
    return True, summary


def check_route(xray: str, route: Route, options: argparse.Namespace) -> tuple[bool, list[str]]:
    """Гоняет один маршрут по обоим критериям.

    Возвращает ``(рабочий, строки отчёта)``. Галочка ставится, только если
    прошли обе проверки: и страна выхода, и нагрузочная проба.
    """
    expected = route.expected_country
    if not expected:
        return False, ["не удалось понять страну из названия маршрута"]

    try:
        with LocalTunnel(xray, route.link) as tunnel:
            # Гео идёт первой: она дешёвая, и если маршрут вообще не встал,
            # незачем тратить полминуты на закачку.
            results = probe(GEO_PROVIDERS, proxy_port=tunnel.port)
            seen = [(name, cc) for name, cc in results if cc]
            if not seen:
                return False, ["страна: туннель не поднялся, ни один гео-сервис не ответил"]

            detail = ", ".join(f"{name}={cc.upper()}" for name, cc in seen)
            if expected not in {cc for _, cc in seen}:
                return False, [f"страна: ожидалась {expected.upper()}, получено {detail}"]
            report = [f"страна: {expected.upper()} ({detail})"]

            passed, summary = traffic_test(
                tunnel.port,
                options.traffic_mb,
                options.streams,
                options.traffic_timeout,
                options.min_speed,
            )
            report.append(f"нагрузка: {summary}")
            return passed, report
    except VpnKitError as exc:
        return False, [str(exc)]


# --- Основной сценарий -----------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Проверить маршруты из vless.md и разметить их ✅/❌",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("vless_file", help="путь к vless.md")
    parser.add_argument(
        "--recheck",
        action="store_true",
        help="перепроверить в том числе уже размеченные маршруты",
    )
    parser.add_argument(
        "--to-clipboard",
        action="store_true",
        help="положить все ссылки в буфер обмена для импорта в v2RayTun",
    )
    parser.add_argument(
        "--only",
        metavar="ПОДСТРОКА",
        help="проверить только маршруты, в названии которых есть эта подстрока",
    )
    parser.add_argument(
        "--allow-system-vpn",
        action="store_true",
        help="не останавливаться, если поднят системный VPN (результаты будут недостоверны)",
    )
    parser.add_argument(
        "--traffic-mb",
        type=int,
        default=TRAFFIC_MB,
        help=f"сколько мегабайт гнать по маршруту (по умолчанию {TRAFFIC_MB})",
    )
    parser.add_argument(
        "--streams",
        type=int,
        default=TRAFFIC_STREAMS,
        help=f"сколько параллельных соединений (по умолчанию {TRAFFIC_STREAMS})",
    )
    parser.add_argument(
        "--traffic-timeout",
        type=int,
        default=TRAFFIC_TIMEOUT,
        help=f"таймаут одного соединения, секунд (по умолчанию {TRAFFIC_TIMEOUT})",
    )
    parser.add_argument(
        "--min-speed",
        type=float,
        default=MIN_SPEED_MBIT,
        help=f"порог средней скорости, Мбит/с (по умолчанию {MIN_SPEED_MBIT:g})",
    )
    args = parser.parse_args()

    try:
        xray = find_xray()

        tunnel = detect_system_tunnel()
        if tunnel and not args.allow_system_vpn:
            fail(
                f"весь трафик машины уходит в системный VPN ({tunnel}).\n"
                "  Локальный туннель окажется вложен в него, REALITY-хендшейк "
                "развалится,\n  и проверка забракует все маршруты подряд, включая "
                "рабочие.\n  Выключите v2RayTun (или другой клиент в режиме TUN) и "
                "повторите,\n  либо запустите с --allow-system-vpn, если понимаете, "
                "что делаете."
            )
            return 1
        if tunnel:
            warn(f"поднят системный VPN ({tunnel}) — результатам верить нельзя")

        path = os.path.abspath(args.vless_file)
        if not os.path.exists(path):
            raise VpnKitError(f"файл не найден: {path}")

        # Сортируем до разбора: перестановка секций сбила бы номера строк,
        # по которым потом проставляются отметки.
        if sort_route_file(path):
            ok(f"{os.path.basename(path)} отсортирован")

        lines, routes = parse_vless_file(path)
        if not routes:
            raise VpnKitError(f"в {path} не нашлось ни одного маршрута")

        if args.to_clipboard:
            payload = "\n".join(r.link for r in routes)
            subprocess.run(["pbcopy"], input=payload, text=True, check=True)
            ok(f"{len(routes)} ссылок в буфере обмена — в v2RayTun импорт из буфера")

        pending = [r for r in routes if args.recheck or not r.mark]
        if args.only:
            pending = [r for r in pending if args.only.lower() in r.label.lower()]
        skipped = len(routes) - len(pending)
        print()
        step(f"маршрутов всего: {len(routes)}, на проверку: {len(pending)}, пропущено: {skipped}")
        step(
            f"нагрузка: {args.traffic_mb} МБ в {args.streams} потока, "
            f"порог {args.min_speed:g} Мбит/с"
        )
        print()

        good = bad = 0
        for index, route in enumerate(pending, 1):
            print(f"[{index}/{len(pending)}] {route.label}")
            passed, report = check_route(xray, route, args)
            for line in report[:-1]:
                print(f"    {line}")
            if passed:
                good += 1
                ok(report[-1])
                apply_mark(lines, route, MARK_OK)
            else:
                bad += 1
                fail(report[-1])
                apply_mark(lines, route, MARK_BAD)
            # Пишем после каждого маршрута: прерванный прогон не теряет работу.
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines).rstrip("\n") + "\n")
            print()

        print(f"итого: {MARK_OK} {good}   {MARK_BAD} {bad}   пропущено {skipped}")
        return 0
    except VpnKitError as exc:
        fail(str(exc))
        return 1
    except KeyboardInterrupt:
        fail("прервано")
        return 130


if __name__ == "__main__":
    sys.exit(main())
