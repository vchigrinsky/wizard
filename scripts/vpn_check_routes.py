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

Разовая проверка на старте (напрямую, мимо туннеля): 2ip.ru должен показывать
Россию. Это ровно то, что в v2RayTun обеспечивает раздельное туннелирование —
российские сайты идут в обход VPN. Проверяется один раз, потому что через
SOCKS-прокси прямой трафик машины не меняется от маршрута к маршруту.

Проверка каждого маршрута (через туннель): страна выхода должна совпасть со
страной зарубежного узла из названия маршрута. Опрашивается несколько
гео-сервисов, потому что их базы расходятся между собой — маршрут считается
рабочим, если ожидаемую страну подтвердил хотя бы один.

Требуется установленный ``xray`` (``brew install xray``).
"""

from __future__ import annotations

import argparse
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

#: Чем проверяем российскую сторону — сначала то, что просил пользователь.
RU_PROVIDERS = [
    ("2ip.ru", "https://2ip.ru/", None),
    ("2ip.ua", "https://api.2ip.ua/geo.json", ("country_code",)),
    ("api.myip.com", "https://api.myip.com", ("cc",)),
]

CURL_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/122 Safari/537.36"


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


def http_get(url: str, proxy_port: int | None = None, timeout: int = 20) -> str | None:
    cmd = ["curl", "-sS", "--max-time", str(timeout), "-A", CURL_UA, url]
    if proxy_port is not None:
        cmd[1:1] = ["--socks5-hostname", f"127.0.0.1:{proxy_port}"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    return proc.stdout


def extract_country(body: str, keys: tuple[str, ...] | None) -> str | None:
    """Достаёт код страны из JSON-ответа или из HTML 2ip.ru."""
    if keys:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return None
        for key in keys:
            value = data.get(key)
            if isinstance(value, str) and len(value) == 2:
                return value.lower()
        return None

    # 2ip.ru отдаёт страну в разметке; ищем и по коду, и по названию.
    import re

    lowered = body.lower()
    for pattern in (
        r'"country_code"\s*:\s*"([a-z]{2})"',
        r"data-country=[\"']([a-z]{2})[\"']",
        r"/flags?/([a-z]{2})\.(?:png|svg|gif)",
    ):
        found = re.search(pattern, lowered)
        if found:
            return found.group(1)
    if "росси" in lowered or "russia" in lowered:
        return "ru"
    return None


def probe(providers, proxy_port: int | None) -> list[tuple[str, str | None]]:
    results = []
    for name, url, keys in providers:
        body = http_get(url, proxy_port=proxy_port)
        results.append((name, extract_country(body, keys) if body else None))
    return results


def baseline_check() -> bool:
    """Разовая проверка: без туннеля мы должны выглядеть как из России."""
    step("проверяю исходное состояние (напрямую, мимо туннеля)")
    for name, url, keys in RU_PROVIDERS:
        body = http_get(url, proxy_port=None)
        country = extract_country(body, keys) if body else None
        if country:
            if country == "ru":
                ok(f"{name}: Россия — раздельное туннелирование в порядке")
                return True
            warn(f"{name}: страна {country.upper()}, а ожидалась RU")
            return False
        warn(f"{name}: не ответил или страна не распозналась, пробую следующий")
    warn("ни один сервис не ответил напрямую")
    return False


def check_route(xray: str, route: Route) -> tuple[bool, str]:
    """Гоняет один маршрут. Возвращает ``(рабочий, человекочитаемая сводка)``."""
    expected = route.expected_country
    if not expected:
        return False, "не удалось понять страну из названия маршрута"

    try:
        with LocalTunnel(xray, route.link) as tunnel:
            results = probe(GEO_PROVIDERS, proxy_port=tunnel.port)
    except VpnKitError as exc:
        return False, str(exc)

    seen = [(name, cc) for name, cc in results if cc]
    if not seen:
        return False, "туннель не поднялся: ни один гео-сервис не ответил"

    countries = {cc for _, cc in seen}
    summary = ", ".join(f"{name}={cc.upper()}" for name, cc in seen)
    if expected in countries:
        return True, f"выход в {expected.upper()} ({summary})"
    return False, f"ожидалась {expected.upper()}, получено: {summary}"


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
        "--skip-baseline",
        action="store_true",
        help="не проверять исходное состояние (например, если вы не в России)",
    )
    parser.add_argument(
        "--to-clipboard",
        action="store_true",
        help="положить все ссылки в буфер обмена для импорта в v2RayTun",
    )
    args = parser.parse_args()

    try:
        xray = find_xray()
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

        if not args.skip_baseline and not baseline_check():
            fail(
                "исходное состояние не сходится: похоже, включён другой VPN "
                "или вы не в России. Выключите посторонние VPN и повторите, "
                "либо запустите с --skip-baseline"
            )
            return 1

        pending = [r for r in routes if args.recheck or not r.mark]
        skipped = len(routes) - len(pending)
        print()
        step(f"маршрутов всего: {len(routes)}, на проверку: {len(pending)}, пропущено: {skipped}")
        print()

        good = bad = 0
        for index, route in enumerate(pending, 1):
            print(f"[{index}/{len(pending)}] {route.label}")
            passed, summary = check_route(xray, route)
            if passed:
                good += 1
                ok(summary)
                apply_mark(lines, route, MARK_OK)
            else:
                bad += 1
                fail(summary)
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
