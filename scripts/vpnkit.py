"""Общие помощники для автоматизации двухузловой VLESS-схемы.

Модуль знает три вещи:

* как разбирать алиасы вида ``hosting_country`` и строить из них имена
  клиентов, outbound'ов и меток маршрутов;
* как ходить по SSH на узел (с мультиплексированием, чтобы десятки вызовов
  подряд не открывали каждый раз новое соединение);
* как разговаривать с API панели 3x-ui, которое слушает только на 127.0.0.1
  удалённой машины — поэтому все вызовы идут через ``curl`` на самом сервере.

Ничего специфичного для конкретного хостинга здесь нет: всё, что нужно
скриптам, выводится из алиаса и из ``~/.ssh/config``.
"""

from __future__ import annotations

import atexit
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
import urllib.parse

# --- Константы схемы -------------------------------------------------------

#: Единственный inbound на каждом узле называется так.
INBOUND_REMARK = "main"

#: Префикс клиента на российском узле: ``vvchigrinskii-to-<hosting>-<country>``.
RU_CLIENT_PREFIX = "vvchigrinskii-to"

#: Префикс клиента на зарубежном узле: ``main-from-<hosting>-<country>``.
FOREIGN_CLIENT_PREFIX = "main-from"

#: Reality-маскировка: чем прикидывается узел в каждой из ролей.
SNI_BY_ROLE = {"ru": "www.yandex.ru", "foreign": "www.google.com"}

#: Версии, на которых схема проверена (см. docs/01-setup-vpn.md).
XUI_VERSION = "v3.5.0"
XRAY_VERSION = "v26.6.27"

#: Порт Xray по умолчанию и запасные, если основной занят.
PREFERRED_PORTS = [443, 8443, 2053]

XUI_INSTALL_URL = "https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh"

ALIAS_RE = re.compile(r"^([a-z0-9][a-z0-9-]*)_([a-z]{2})$")


class VpnKitError(RuntimeError):
    """Ошибка, которую имеет смысл показать пользователю как есть."""


#: Переменные, которыми окружение может незаметно увести трафик в прокси.
PROXY_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy",
)


def env_without_proxy() -> dict[str, str]:
    """Окружение без прокси-переменных.

    Если приложению прописан прокси через переменные окружения, их наследуют
    все запущенные им процессы — в том числе ``curl``, которым мы измеряем
    туннель. Тогда замер молча уходит мимо туннеля и показывает страну прокси.
    Поэтому всё, что должно идти именно своим маршрутом, запускается с
    вычищенным окружением.
    """
    env = dict(os.environ)
    for name in PROXY_ENV_VARS:
        env.pop(name, None)
    return env


# --- Алиасы, имена, метки --------------------------------------------------


def parse_alias(alias: str) -> tuple[str, str]:
    """``timeweb_nl`` -> ``("timeweb", "nl")``."""
    m = ALIAS_RE.match(alias)
    if not m:
        raise VpnKitError(
            f"алиас {alias!r} не по формату; ожидается <hosting>_<country>, "
            "например timeweb_nl или selectel_kz"
        )
    return m.group(1), m.group(2)


def flag(country: str) -> str:
    """``nl`` -> ``🇳🇱`` (regional indicator symbols)."""
    return "".join(chr(0x1F1E6 + ord(c) - ord("a")) for c in country.lower())


FLAG_RE = re.compile("[\U0001f1e6-\U0001f1ff]{2}")


def country_from_flag(text: str) -> str | None:
    """``🇰🇿 selectel`` -> ``kz`` (по первому флагу в строке)."""
    letters: list[str] = []
    for char in text:
        code = ord(char)
        if 0x1F1E6 <= code <= 0x1F1FF:
            letters.append(chr(code - 0x1F1E6 + ord("a")))
            if len(letters) == 2:
                return "".join(letters)
        elif letters:
            break
    return None


def split_node_token(text: str) -> tuple[str, str]:
    """``🇰🇿 selectel`` -> ``("selectel", "kz")``."""
    return FLAG_RE.sub("", text).strip(), country_from_flag(text) or ""


def route_label(foreign_alias: str, ru_alias: str) -> str:
    """Метка маршрута в том же виде, в каком она лежит в vless.md."""
    fh, fc = parse_alias(foreign_alias)
    rh, rc = parse_alias(ru_alias)
    return f"{flag(fc)} {fh} ← {flag(rc)} {rh}"


def panel_label(alias: str) -> str:
    """Метка узла для panels.md: ``timeweb_ru`` -> ``🇷🇺 timeweb``."""
    hosting, country = parse_alias(alias)
    return f"{flag(country)} {hosting}"


def ru_client_email(foreign_alias: str) -> str:
    fh, fc = parse_alias(foreign_alias)
    return f"{RU_CLIENT_PREFIX}-{fh}-{fc}"


def foreign_client_email(ru_alias: str) -> str:
    rh, rc = parse_alias(ru_alias)
    return f"{FOREIGN_CLIENT_PREFIX}-{rh}-{rc}"


def outbound_tag(foreign_alias: str) -> str:
    fh, fc = parse_alias(foreign_alias)
    return f"{fh}-{fc}-main"


def encode_label(label: str) -> str:
    """Метка -> percent-encoding для фрагмента vless-ссылки."""
    return urllib.parse.quote(label, safe="")


def replace_link_label(link: str, label: str) -> str:
    """Меняет хвост ``#...`` у vless-ссылки на нашу метку."""
    base = link.split("#", 1)[0]
    return f"{base}#{encode_label(label)}"


# --- Случайные значения в стиле 3x-ui --------------------------------------


def random_short_ids() -> list[str]:
    """Пул shortId'ов ровно как их генерирует панель: по одному на каждую
    чётную длину от 2 до 16 hex-символов."""
    ids = [secrets.token_hex(n // 2) for n in range(2, 17, 2)]
    # порядок в панели перемешан; воспроизводим это, чтобы диффы не смущали
    secrets.SystemRandom().shuffle(ids)
    return ids


def random_spider_x() -> str:
    """``spiderX`` в ссылках и outbound'ах панели — ``/`` + 15 hex-символов."""
    return "/" + secrets.token_hex(8)[:15]


def random_inbound_spider_x() -> str:
    """``spiderX`` самого inbound'а — 16 символов base62."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    rng = secrets.SystemRandom()
    return "/" + "".join(rng.choice(alphabet) for _ in range(16))


# --- ~/.ssh/config ---------------------------------------------------------


def ssh_config_path() -> str:
    return os.path.expanduser("~/.ssh/config")


def parse_ssh_config() -> dict[str, dict[str, str]]:
    """Читает ``~/.ssh/config`` в словарь ``{host: {ключ: значение}}``."""
    path = ssh_config_path()
    if not os.path.exists(path):
        return {}
    hosts: dict[str, dict[str, str]] = {}
    current: str | None = None
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, value = parts[0].lower(), parts[1].strip()
            if key == "host":
                current = value
                hosts.setdefault(current, {})
            elif current is not None:
                hosts[current][key] = value
    return hosts


def resolve_host(alias: str) -> tuple[str, str]:
    """По алиасу ``timeweb_nl`` находит в ``~/.ssh/config`` запись
    ``timeweb_nl_<IP>`` и возвращает ``(host_alias, ip)``."""
    parse_alias(alias)  # заодно валидируем формат
    hosts = parse_ssh_config()
    matches = [h for h in hosts if h.startswith(alias + "_")]
    if not matches:
        raise VpnKitError(
            f"в ~/.ssh/config нет записи для {alias!r}; "
            f"сначала заведите ключ: python scripts/vpn_ssh_key.py {alias} IP PASSWORD"
        )
    if len(matches) > 1:
        raise VpnKitError(
            f"в ~/.ssh/config несколько записей под {alias!r}: {', '.join(sorted(matches))}; "
            "оставьте одну"
        )
    host_alias = matches[0]
    ip = hosts[host_alias].get("hostname") or host_alias[len(alias) + 1 :]
    return host_alias, ip


# --- SSH -------------------------------------------------------------------


class Ssh:
    """SSH-соединение с мультиплексированием.

    Первый вызов поднимает мастер-сокет, все последующие переиспользуют его,
    поэтому серия из полусотни вызовов API отрабатывает без задержек на
    установку соединения.
    """

    def __init__(self, host_alias: str, quiet: bool = False):
        self.host = host_alias
        self.quiet = quiet
        # Путь к управляющему сокету держим коротким: ssh дописывает к нему
        # ~17 случайных символов, а лимит на длину unix-сокета в macOS — 104,
        # так что путь во временной директории пользователя уже не влезает.
        digest = hashlib.sha1(f"{os.getpid()}-{host_alias}".encode()).hexdigest()[:10]
        self._ctl = f"/tmp/.vpnkit-{digest}"
        self._sudo: str | None = None
        atexit.register(self.close)

    @property
    def _base(self) -> list[str]:
        return [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=15",
            "-o", "ControlMaster=auto",
            "-o", f"ControlPath={self._ctl}",
            "-o", "ControlPersist=120",
            self.host,
        ]

    def run(
        self,
        command: str,
        stdin: str | None = None,
        check: bool = True,
        timeout: int = 180,
    ) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            self._base + ["--", command],
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and proc.returncode != 0:
            raise VpnKitError(
                f"[{self.host}] команда завершилась с кодом {proc.returncode}: {command}\n"
                f"{proc.stderr.strip() or proc.stdout.strip()}"
            )
        return proc

    @property
    def sudo(self) -> str:
        """Пустая строка для root, иначе ``sudo -n``."""
        if self._sudo is None:
            uid = self.run("id -u", check=False).stdout.strip()
            self._sudo = "" if uid == "0" else "sudo -n "
        return self._sudo

    def sudo_run(self, command: str, **kwargs) -> subprocess.CompletedProcess:
        return self.run(f"{self.sudo}{command}", **kwargs)

    def alive(self, timeout: int = 15) -> bool:
        try:
            return self.run("true", check=False, timeout=timeout).returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def wait_until_alive(self, deadline_seconds: int = 300) -> None:
        """Ждёт, пока сервер снова начнёт отвечать (после reboot)."""
        self.close()
        started = time.time()
        while time.time() - started < deadline_seconds:
            if self.alive():
                return
            time.sleep(5)
        raise VpnKitError(f"[{self.host}] сервер не поднялся за {deadline_seconds} секунд")

    def close(self) -> None:
        if os.path.exists(self._ctl):
            subprocess.run(
                ["ssh", "-o", f"ControlPath={self._ctl}", "-O", "exit", self.host],
                capture_output=True,
                text=True,
            )


# --- API панели 3x-ui ------------------------------------------------------

#: Преамбула, которая подтягивает креды панели из файла, оставленного установщиком.
#:
#: Схему берём не наугад: часть узлов ставилась с TLS на самой панели, и там
#: она слушает https. Установщик записывает готовый адрес в XUI_ACCESS_URL —
#: по нему и определяем. Проверку сертификата снимаем всегда: идём на
#: 127.0.0.1, где у панели самоподписанный сертификат на внешний адрес, так
#: что проверка не прошла бы никогда, а трафик наружу при этом не выходит.
_PANEL_ENV = (
    'set -a; . /etc/x-ui/install-result.env; set +a; '
    'case "$XUI_ACCESS_URL" in https://*) S=https;; *) S=http;; esac; '
    'B="${S}://127.0.0.1:${XUI_PANEL_PORT}/${XUI_WEB_BASE_PATH}"; '
    'A="Authorization: Bearer ${XUI_API_TOKEN}"; '
)


class Panel:
    """Клиент API 3x-ui.

    Панель по умолчанию слушает публично, но полагаться на это не хочется:
    порт может быть закрыт файрволом хостинга. Поэтому каждый запрос
    выполняется через ``curl`` уже на самом сервере, на 127.0.0.1 — так
    работает одинаково на любом хостинге и токен не светится в локальных
    аргументах процессов.
    """

    def __init__(self, ssh: Ssh):
        self.ssh = ssh

    # -- низкий уровень --

    def installed(self) -> bool:
        return (
            self.ssh.run(
                "test -f /etc/x-ui/install-result.env && test -x /usr/local/x-ui/x-ui",
                check=False,
            ).returncode
            == 0
        )

    def _request(self, shell: str, stdin: str | None = None, timeout: int = 180) -> dict:
        proc = self.ssh.run(
            f"{self.ssh.sudo}sh -c {shlex.quote(_PANEL_ENV + shell)}",
            stdin=stdin,
            timeout=timeout,
        )
        body = proc.stdout.strip()
        if not body:
            raise VpnKitError(f"[{self.ssh.host}] панель вернула пустой ответ на: {shell}")
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise VpnKitError(
                f"[{self.ssh.host}] панель вернула не JSON: {body[:300]}"
            ) from exc
        if not data.get("success", False):
            raise VpnKitError(
                f"[{self.ssh.host}] панель отклонила запрос: {data.get('msg') or data}"
            )
        return data

    def get(self, path: str, timeout: int = 180) -> dict:
        return self._request(f'curl -sS -L -k -H "$A" "$B{path}"', timeout=timeout)

    def post_json(self, path: str, payload: dict | None = None, timeout: int = 180) -> dict:
        cmd = (
            'curl -sS -L -k -X POST -H "$A" -H "Content-Type: application/json" '
            f'--data-binary @- "$B{path}"'
        )
        return self._request(cmd, stdin=json.dumps(payload or {}), timeout=timeout)

    def post_empty(self, path: str, timeout: int = 300) -> dict:
        return self._request(f'curl -sS -L -k -X POST -H "$A" "$B{path}"', timeout=timeout)

    def post_form_field(self, path: str, field: str, value: str, timeout: int = 180) -> dict:
        """POST одного длинного поля формы. Значение уезжает через stdin во
        временный файл, чтобы не упереться в лимит длины командной строки."""
        cmd = (
            't=$(mktemp); cat > "$t"; '
            f'curl -sS -L -k -X POST -H "$A" --data-urlencode {shlex.quote(field)}@"$t" "$B{path}"; '
            'rc=$?; rm -f "$t"; exit $rc'
        )
        return self._request(cmd, stdin=value, timeout=timeout)

    # -- inbounds и клиенты --

    def inbounds(self) -> list[dict]:
        return self.get("/panel/api/inbounds/list").get("obj") or []

    def find_inbound(self, remark: str = INBOUND_REMARK) -> dict | None:
        for inbound in self.inbounds():
            if inbound.get("remark") == remark:
                return inbound
        return None

    def add_inbound(self, payload: dict) -> dict:
        return self.post_json("/panel/api/inbounds/add", payload)

    def add_client(self, email: str, inbound_id: int) -> dict:
        return self.post_json(
            "/panel/api/clients/add",
            {"client": {"email": email, "enable": True}, "inboundIds": [inbound_id]},
        )

    def client_links(self, email: str) -> list[str]:
        quoted = urllib.parse.quote(email, safe="")
        return self.get(f"/panel/api/clients/links/{quoted}").get("obj") or []

    def new_x25519(self) -> dict:
        return self.get("/panel/api/server/getNewX25519Cert")["obj"]

    # -- xray-конфиг (outbounds + routing) --

    def xray_setting(self) -> dict:
        obj = self.post_empty("/panel/api/xray/")["obj"]
        if isinstance(obj, str):
            obj = json.loads(obj)
        setting = obj["xraySetting"]
        return json.loads(setting) if isinstance(setting, str) else setting

    def save_xray_setting(self, setting: dict) -> None:
        self.post_form_field(
            "/panel/api/xray/update", "xraySetting", json.dumps(setting)
        )

    def restart_xray(self) -> None:
        self.post_empty("/panel/api/server/restartXrayService")

    def xray_version(self) -> str | None:
        obj = self.get("/panel/api/server/status").get("obj") or {}
        return (obj.get("xray") or {}).get("version")

    def install_xray(self, version: str) -> None:
        self.post_empty(f"/panel/api/server/installXray/{version}", timeout=600)

    # -- доступы к самой панели --

    def credentials(self, ip: str | None = None) -> dict[str, str]:
        """Достаёт URL, логин и пароль панели из файла, оставленного установщиком.

        Значения там записаны через ``printf %q``, поэтому не парсим файл
        руками, а даём шеллу его прочитать и распечатать уже развёрнутым.
        """
        dump = (
            "set -a; . /etc/x-ui/install-result.env; set +a; "
            'printf "%s\\n%s\\n%s\\n%s\\n%s\\n" '
            '"$XUI_ACCESS_URL" "$XUI_USERNAME" "$XUI_PASSWORD" '
            '"$XUI_PANEL_PORT" "$XUI_WEB_BASE_PATH"'
        )
        proc = self.ssh.run(f"{self.ssh.sudo}sh -c {shlex.quote(dump)}")
        fields = (proc.stdout.splitlines() + [""] * 5)[:5]
        url, username, password, port, base_path = (f.strip() for f in fields)

        # Установщик подставляет в URL адрес из XUI_SERVER_IP; если его при
        # установке не передали, хост в URL пустой — тогда собираем сами.
        if ip and not urllib.parse.urlsplit(url).hostname:
            url = f"http://{ip}:{port}/{base_path}"

        if not (url and username and password):
            raise VpnKitError(
                f"[{self.ssh.host}] в /etc/x-ui/install-result.env нет полного набора "
                "доступов к панели"
            )
        return {"url": url, "username": username, "password": password}


# --- Сортировка рабочих файлов ---------------------------------------------

#: Маркеры проверки, которые дописывает vpn_check_routes.py.
STATUS_MARKS = ("✅", "❌")


def strip_marks(text: str) -> str:
    for mark in STATUS_MARKS:
        text = text.replace(mark, "")
    return text.strip()


def split_sections(lines: list[str]) -> tuple[list[str], list[tuple[str, list[str]]]]:
    """Режет файл на шапку и секции ``## ...`` вместе с их содержимым."""
    preamble: list[str] = []
    sections: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None

    for line in lines:
        if line.startswith("## "):
            if current:
                sections.append(current)
            current = (line, [])
        elif current is None:
            preamble.append(line)
        else:
            current[1].append(line)
    if current:
        sections.append(current)
    return preamble, sections


def render_sections(preamble: list[str], sections: list[tuple[str, list[str]]]) -> list[str]:
    out = list(preamble)
    while out and not out[-1].strip():
        out.pop()
    for header, body in sections:
        trimmed = list(body)
        while trimmed and not trimmed[-1].strip():
            trimmed.pop()
        out += ["", header] + trimmed
    return out


def route_sort_key(header: str) -> tuple:
    """Порядок маршрутов: по зарубежному узлу, внутри — по российскому.

    Нераспознанные заголовки уезжают в конец, сохраняя исходный порядок
    между собой (сортировка стабильная).
    """
    parts = strip_marks(header[3:]).split("←")
    if len(parts) != 2:
        return (1, "", "", "", "")
    foreign_hosting, foreign_country = split_node_token(parts[0])
    ru_hosting, ru_country = split_node_token(parts[1])
    if not (foreign_hosting and foreign_country and ru_hosting):
        return (1, "", "", "", "")
    return (0, foreign_hosting, foreign_country, ru_hosting, ru_country)


def panel_sort_key(header: str) -> tuple:
    """Порядок узлов: по хостингу, внутри — по стране."""
    hosting, country = split_node_token(strip_marks(header[3:]))
    if not (hosting and country):
        return (1, "", "")
    return (0, hosting, country)


def sort_file(path: str, key) -> bool:
    """Пересобирает файл с отсортированными секциями.

    Возвращает True, если порядок действительно поменялся. Содержимое секций
    не трогается — переставляются только они целиком вместе с заголовками.
    """
    if not os.path.exists(path):
        return False

    with open(path, encoding="utf-8") as fh:
        original = fh.read()

    preamble, sections = split_sections(original.splitlines())
    if len(sections) < 2:
        return False

    ordered = sorted(sections, key=lambda section: key(section[0]))
    if ordered == sections:
        return False

    updated = "\n".join(render_sections(preamble, ordered)).rstrip("\n") + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(updated)
    return True


def sort_route_file(path: str) -> bool:
    return sort_file(path, route_sort_key)


def sort_panel_file(path: str) -> bool:
    return sort_file(path, panel_sort_key)


# --- panels.md -------------------------------------------------------------


def write_panel_entry(path: str, alias: str, creds: dict[str, str]) -> str:
    """Дозаписывает доступы к панели. Существующую запись не трогает.

    Возвращает описание того, что произошло. Файл в любом случае остаётся
    отсортированным — даже если запись уже была.
    """
    label = panel_label(alias)

    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    else:
        lines = ["# 3x-ui panels", ""]

    existed = any(
        line.startswith("## ") and line[3:].strip() == label for line in lines
    )

    if not existed:
        while lines and not lines[-1].strip():
            lines.pop()
        lines += [
            "",
            f"## {label}",
            f"- URL: {creds['url']}",
            f"- Логин: {creds['username']}",
            f"- Пароль: {creds['password']}",
            "",
        ]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines).rstrip("\n") + "\n")
        os.chmod(path, 0o600)

    resorted = sort_panel_file(path)
    action = "уже записан, без изменений" if existed else "добавлены доступы к панели"
    return f"{action}, отсортирован" if resorted else action


# --- Вывод -----------------------------------------------------------------


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") != "dumb"


def step(message: str) -> None:
    prefix = "\033[36m→\033[0m" if _supports_color() else "->"
    print(f"{prefix} {message}", flush=True)


def ok(message: str) -> None:
    prefix = "\033[32m✓\033[0m" if _supports_color() else "ok"
    print(f"{prefix} {message}", flush=True)


def warn(message: str) -> None:
    prefix = "\033[33m!\033[0m" if _supports_color() else "!!"
    print(f"{prefix} {message}", flush=True)


def fail(message: str) -> None:
    prefix = "\033[31m✗\033[0m" if _supports_color() else "xx"
    print(f"{prefix} {message}", file=sys.stderr, flush=True)
