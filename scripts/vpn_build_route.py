#!/usr/bin/env python3
"""Шаг 1: собрать двухузловую VLESS-связку целиком, без участия человека.

    python scripts/vpn_build_route.py ALIAS_RU ALIAS_FOREIGN

Например::

    python scripts/vpn_build_route.py timeweb_ru selectel_kz

Скрипт воспроизводит docs/01-setup-vpn.md от начала до конца:

* при необходимости готовит голый сервер — apt update/upgrade, подбор
  свободного порта, неинтерактивная установка 3x-ui и откат Xray на
  проверенную версию;
* на зарубежном узле поднимает inbound ``main`` (Reality под www.google.com)
  и клиента ``main-from-<хостинг>-<страна>``;
* на российском узле поднимает inbound ``main`` (Reality под www.yandex.ru),
  клиента ``vvchigrinskii-to-<хостинг>-<страна>``, outbound
  ``<хостинг>-<страна>-main`` на зарубежный узел и routing rule, связывающий
  клиента с этим outbound'ом;
* забирает готовую vless-ссылку, подменяет в ней метку на
  ``🇳🇱 hosting ← 🇷🇺 hosting`` и дописывает в vless.md.

Каждый шаг идемпотентен: то, что уже настроено, переиспользуется, а не
создаётся заново. Поэтому скрипт одинаково безопасно запускать и на новом
сервере, и на том, где связки уже собирались руками.

Предусловие: на оба узла есть вход по ключу (см. vpn_ssh_key.py).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_panel_creds import record_panel  # noqa: E402
from vpnkit import (  # noqa: E402
    INBOUND_REMARK,
    PREFERRED_PORTS,
    SNI_BY_ROLE,
    XRAY_VERSION,
    XUI_INSTALL_URL,
    XUI_VERSION,
    Panel,
    Ssh,
    VpnKitError,
    fail,
    foreign_client_email,
    ok,
    outbound_tag,
    parse_alias,
    random_inbound_spider_x,
    random_short_ids,
    random_spider_x,
    replace_link_label,
    resolve_host,
    route_label,
    ru_client_email,
    step,
    warn,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_VLESS_FILE = os.path.join(REPO_ROOT, "vless.md")
DEFAULT_PANELS_FILE = os.path.join(REPO_ROOT, "panels.md")

#: Маркеры проверки, которые дописывает vpn_check_routes.py.
STATUS_MARKS = ("✅", "❌")


def as_dict(value) -> dict:
    """Панель отдаёт вложенные структуры то объектом, то строкой JSON."""
    if isinstance(value, str):
        return json.loads(value) if value.strip() else {}
    return value or {}


# --- Подготовка голого сервера --------------------------------------------


def pick_port(ssh: Ssh) -> int:
    """Первый свободный порт из списка предпочтительных."""
    for port in PREFERRED_PORTS:
        busy = ssh.sudo_run(
            f"ss -ltn 'sport = :{port}' 2>/dev/null | tail -n +2", check=False
        ).stdout.strip()
        if not busy:
            return port
        warn(f"порт {port} занят, пробую следующий")
    raise VpnKitError(
        f"все порты из {PREFERRED_PORTS} заняты — освободите один или расширьте PREFERRED_PORTS"
    )


def bootstrap_server(ssh: Ssh, ip: str) -> None:
    """apt + установка 3x-ui + фиксация версии Xray на голой машине."""
    step(f"[{ssh.host}] обновляю пакеты (это долго, несколько минут)")
    ssh.sudo_run(
        "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
        "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -qq "
        "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold && "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates",
        timeout=1800,
    )

    if ssh.run("test -f /var/run/reboot-required", check=False).returncode == 0:
        step(f"[{ssh.host}] требуется перезагрузка, перезагружаю и жду")
        ssh.sudo_run("(sleep 1; reboot) >/dev/null 2>&1 &", check=False)
        ssh.wait_until_alive()
        ok(f"[{ssh.host}] сервер вернулся")

    port = pick_port(ssh)
    if port != PREFERRED_PORTS[0]:
        warn(f"[{ssh.host}] Xray будет слушать на {port}, а не на {PREFERRED_PORTS[0]}")

    step(f"[{ssh.host}] ставлю 3x-ui {XUI_VERSION}")
    ssh.sudo_run(
        f"curl -fLsS {shlex.quote(XUI_INSTALL_URL)} -o /tmp/3xui-install.sh && "
        "XUI_NONINTERACTIVE=1 XUI_SSL_MODE=none XUI_DB_TYPE=sqlite "
        f"XUI_SERVER_IP={shlex.quote(ip)} "
        f"bash /tmp/3xui-install.sh {shlex.quote(XUI_VERSION)} && rm -f /tmp/3xui-install.sh",
        timeout=1800,
    )
    ok(f"[{ssh.host}] 3x-ui установлена")


def ensure_panel(ssh: Ssh, ip: str) -> Panel:
    """Гарантирует рабочую панель и нужную версию ядра Xray."""
    panel = Panel(ssh)
    if not panel.installed():
        bootstrap_server(ssh, ip)
        panel = Panel(ssh)
        if not panel.installed():
            raise VpnKitError(f"[{ssh.host}] 3x-ui так и не установилась")
    else:
        ok(f"[{ssh.host}] 3x-ui уже стоит")

    current = panel.xray_version()
    wanted = XRAY_VERSION.lstrip("v")
    if current != wanted:
        step(f"[{ssh.host}] Xray {current or '?'} → {XRAY_VERSION}")
        panel.install_xray(XRAY_VERSION)
        ok(f"[{ssh.host}] Xray переключён на {XRAY_VERSION}")
    else:
        ok(f"[{ssh.host}] Xray уже {XRAY_VERSION}")
    return panel


# --- Inbound ---------------------------------------------------------------


def build_inbound_payload(ip: str, role: str, port: int, keys: dict) -> dict:
    """Полезная нагрузка для создания inbound'а — один в один как её кладёт
    панель, когда inbound заводят руками по инструкции."""
    sni = SNI_BY_ROLE[role]
    return {
        "enable": True,
        "remark": INBOUND_REMARK,
        "listen": "",
        "port": port,
        "protocol": "vless",
        "expiryTime": 0,
        "total": 0,
        "shareAddrStrategy": "custom",
        "shareAddr": ip,
        "settings": {"clients": [], "decryption": "none", "encryption": "none"},
        "streamSettings": {
            "network": "tcp",
            "tcpSettings": {"acceptProxyProtocol": False, "header": {"type": "none"}},
            "security": "reality",
            "realitySettings": {
                "show": False,
                "xver": 0,
                "target": f"{sni}:443",
                "serverNames": [sni],
                "privateKey": keys["privateKey"],
                "minClientVer": "",
                "maxClientVer": "",
                "maxTimediff": 0,
                "shortIds": random_short_ids(),
                "mldsa65Seed": "",
                "settings": {
                    "publicKey": keys["publicKey"],
                    "fingerprint": "firefox",
                    "serverName": "",
                    "spiderX": random_inbound_spider_x(),
                    "mldsa65Verify": "",
                },
            },
        },
        "sniffing": {"enabled": False},
    }


def ensure_inbound(panel: Panel, ssh: Ssh, ip: str, role: str) -> dict:
    inbound = panel.find_inbound(INBOUND_REMARK)
    if inbound:
        ok(f"[{ssh.host}] inbound '{INBOUND_REMARK}' уже есть (порт {inbound['port']})")
        return inbound

    port = pick_port(ssh)
    step(f"[{ssh.host}] создаю inbound '{INBOUND_REMARK}' на порту {port}")
    keys = panel.new_x25519()
    panel.add_inbound(build_inbound_payload(ip, role, port, keys))

    inbound = panel.find_inbound(INBOUND_REMARK)
    if not inbound:
        raise VpnKitError(f"[{ssh.host}] inbound создан, но не нашёлся в списке")
    ok(f"[{ssh.host}] inbound '{INBOUND_REMARK}' создан")
    return inbound


# --- Клиенты ---------------------------------------------------------------


def find_client(inbound: dict, email: str) -> dict | None:
    for client in as_dict(inbound.get("settings")).get("clients", []):
        if client.get("email") == email:
            return client
    return None


def ensure_client(panel: Panel, ssh: Ssh, inbound: dict, email: str) -> tuple[dict, dict, bool]:
    """Возвращает ``(клиент, актуальный inbound, создавали ли заново)``."""
    client = find_client(inbound, email)
    if client:
        ok(f"[{ssh.host}] клиент {email} уже есть")
        return client, inbound, False

    step(f"[{ssh.host}] создаю клиента {email}")
    panel.add_client(email, inbound["id"])

    inbound = panel.find_inbound(INBOUND_REMARK) or inbound
    client = find_client(inbound, email)
    if not client:
        raise VpnKitError(f"[{ssh.host}] клиент {email} создан, но не нашёлся в inbound'е")
    ok(f"[{ssh.host}] клиент {email} создан")
    return client, inbound, True


# --- Outbound и routing на российском узле ---------------------------------


def build_outbound(tag: str, foreign_ip: str, foreign_inbound: dict, uuid: str) -> dict:
    """Outbound на зарубежный узел, собранный из его же inbound'а —
    ровно те значения, которые в инструкции переносятся руками из vless-ссылки."""
    reality = as_dict(foreign_inbound.get("streamSettings")).get("realitySettings", {})
    short_ids = reality.get("shortIds") or []
    if not short_ids:
        raise VpnKitError("у зарубежного inbound'а пустой список shortIds")

    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "address": foreign_ip,
            "port": foreign_inbound["port"],
            "id": uuid,
            "flow": "",
            "encryption": "none",
        },
        "streamSettings": {
            "network": "tcp",
            "tcpSettings": {"header": {"type": "none"}},
            "security": "reality",
            "finalmask": {"tcp": []},
            "realitySettings": {
                "publicKey": reality.get("settings", {}).get("publicKey", ""),
                "fingerprint": "firefox",
                "serverName": (reality.get("serverNames") or [SNI_BY_ROLE["foreign"]])[0],
                "shortId": secrets.choice(short_ids),
                "spiderX": random_spider_x(),
                "mldsa65Verify": "",
            },
        },
    }


def ensure_outbound_and_routing(
    panel: Panel,
    ssh: Ssh,
    tag: str,
    client_email: str,
    foreign_ip: str,
    foreign_inbound: dict,
    uuid: str,
) -> bool:
    """Досоглашает outbound и routing rule. Возвращает True, если что-то поменяли."""
    setting = panel.xray_setting()
    outbounds = setting.setdefault("outbounds", [])
    routing = setting.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    changed = False

    existing = next((o for o in outbounds if o.get("tag") == tag), None)
    if existing:
        # Узел могли пересоздать — тогда ключи Reality сменились и старый
        # outbound молча перестал работать. Сверяем и чиним.
        wanted = build_outbound(tag, foreign_ip, foreign_inbound, uuid)
        cur_reality = as_dict(existing.get("streamSettings")).get("realitySettings", {})
        new_reality = wanted["streamSettings"]["realitySettings"]
        stale = (
            as_dict(existing.get("settings")).get("id") != uuid
            or as_dict(existing.get("settings")).get("address") != foreign_ip
            or cur_reality.get("publicKey") != new_reality["publicKey"]
        )
        if stale:
            outbounds[outbounds.index(existing)] = wanted
            changed = True
            warn(f"[{ssh.host}] outbound {tag} устарел — переписал под текущие ключи")
        else:
            ok(f"[{ssh.host}] outbound {tag} уже есть")
    else:
        step(f"[{ssh.host}] создаю outbound {tag}")
        outbounds.append(build_outbound(tag, foreign_ip, foreign_inbound, uuid))
        changed = True

    rule = next(
        (r for r in rules if r.get("outboundTag") == tag and client_email in (r.get("user") or [])),
        None,
    )
    if rule:
        ok(f"[{ssh.host}] routing rule {client_email} → {tag} уже есть")
    else:
        step(f"[{ssh.host}] создаю routing rule {client_email} → {tag}")
        rules.append(
            {
                "type": "field",
                "enabled": True,
                "user": [client_email],
                "outboundTag": tag,
            }
        )
        changed = True

    if changed:
        panel.save_xray_setting(setting)
        ok(f"[{ssh.host}] конфиг Xray сохранён")
    return changed


# --- vless.md --------------------------------------------------------------


def verify_outbound(panel: Panel, ssh: Ssh, tag: str, expected_country: str) -> None:
    """Проверяет хоп «российский узел → зарубежный» силами самой панели.

    Это то же самое, что значок молнии в интерфейсе: панель поднимает
    временный экземпляр Xray, ходит через outbound наружу и отдаёт задержку и
    страну выхода. Локальную сеть при этом не трогает вообще.
    """
    step(f"[{ssh.host}] проверяю outbound {tag}")
    setting = panel.xray_setting()
    outbound = next((o for o in setting.get("outbounds", []) if o.get("tag") == tag), None)
    if not outbound:
        warn(f"[{ssh.host}] outbound {tag} не найден — проверку пропускаю")
        return

    try:
        result = panel.post_form_field(
            "/panel/api/xray/testOutbound", "outbound", json.dumps(outbound), timeout=120
        )
    except VpnKitError as exc:
        warn(f"[{ssh.host}] проверить outbound не удалось: {exc}")
        return

    obj = result.get("obj") or {}
    if not obj.get("success"):
        warn(f"[{ssh.host}] outbound {tag} не отвечает: {obj.get('msg') or obj}")
        return

    egress = obj.get("egress") or {}
    country = (egress.get("country") or "").lower()
    delay = obj.get("delay")
    where = f"{egress.get('ipv4') or '?'} / {country.upper() or '?'}"
    if country and country != expected_country:
        warn(
            f"[{ssh.host}] выход через {where}, а ожидалась страна "
            f"{expected_country.upper()} — проверьте, тот ли это сервер"
        )
    else:
        ok(f"[{ssh.host}] хоп до зарубежного узла работает: {where}, {delay} мс")


def strip_mark(header: str) -> str:
    """``## 🇳🇱 timeweb ← 🇷🇺 timeweb ✅`` -> ``🇳🇱 timeweb ← 🇷🇺 timeweb``."""
    text = header.lstrip("#").strip()
    for mark in STATUS_MARKS:
        text = text.replace(mark, "")
    return text.strip()


def link_identity(link: str) -> tuple:
    """Смысловая часть ссылки, по которой решается, менялся ли маршрут.

    ``sid`` панель выбирает случайно из пула при каждом обращении, а ``spx``
    вообще нужен только клиенту, — поэтому сравнивать ссылки побайтово нельзя:
    иначе повторный запуск переписывал бы файл на ровном месте.
    """
    import urllib.parse as up

    parsed = up.urlsplit(link)
    query = up.parse_qs(parsed.query)
    return (
        parsed.username or "",           # UUID клиента
        parsed.hostname or "",           # адрес российского узла
        parsed.port or 0,
        query.get("pbk", [""])[0],       # публичный ключ Reality
        query.get("sni", [""])[0],
        query.get("security", [""])[0],
        query.get("type", [""])[0],
    )


def write_vless_entry(path: str, label: str, link: str) -> str:
    """Дописывает или обновляет секцию маршрута. Возвращает, что было сделано."""
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    else:
        lines = ["# VLESS keys", ""]

    for i, line in enumerate(lines):
        if line.startswith("## ") and strip_mark(line) == label:
            # Ссылка идёт первой непустой строкой после заголовка.
            for j in range(i + 1, len(lines)):
                if lines[j].startswith("vless://"):
                    if link_identity(lines[j].strip()) == link_identity(link):
                        return "уже записан, без изменений"
                    lines[j] = link
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write("\n".join(lines).rstrip("\n") + "\n")
                    return "ссылка обновлена"
                if lines[j].startswith("## "):
                    break
            break

    while lines and not lines[-1].strip():
        lines.pop()
    lines += ["", f"## {label}", link, ""]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines).rstrip("\n") + "\n")
    return "добавлен новый маршрут"


# --- Основной сценарий -----------------------------------------------------


def record_panel_creds(alias: str, ssh: Ssh, panels_file: str) -> None:
    """Складывает доступы к панели узла в panels.md, если их там ещё нет."""
    try:
        action = record_panel(alias, panels_file, ssh=ssh)
        ok(f"[{ssh.host}] {os.path.basename(panels_file)}: {action}")
    except VpnKitError as exc:
        # Связку это не ломает — маршрут уже собран, просто не записались доступы.
        warn(f"[{ssh.host}] доступы к панели не записались: {exc}")


def build_route(ru_alias: str, foreign_alias: str, vless_file: str, panels_file: str) -> str:
    parse_alias(ru_alias)
    parse_alias(foreign_alias)
    if ru_alias == foreign_alias:
        raise VpnKitError("российский и зарубежный узлы не могут быть одним сервером")

    ru_host, ru_ip = resolve_host(ru_alias)
    foreign_host, foreign_ip = resolve_host(foreign_alias)
    label = route_label(foreign_alias, ru_alias)

    print(f"\n=== {label} ===")
    print(f"    RU:      {ru_host} ({ru_ip})")
    print(f"    FOREIGN: {foreign_host} ({foreign_ip})\n")

    ru_ssh = Ssh(ru_host)
    foreign_ssh = Ssh(foreign_host)

    for ssh in (ru_ssh, foreign_ssh):
        if not ssh.alive():
            raise VpnKitError(
                f"нет доступа по ключу к {ssh.host}; проверьте: ssh {ssh.host}"
            )

    # 1. Зарубежный узел: панель, inbound, клиент.
    print("--- зарубежный узел ---")
    foreign_panel = ensure_panel(foreign_ssh, foreign_ip)
    record_panel_creds(foreign_alias, foreign_ssh, panels_file)
    foreign_inbound = ensure_inbound(foreign_panel, foreign_ssh, foreign_ip, "foreign")
    foreign_email = foreign_client_email(ru_alias)
    foreign_client, foreign_inbound, foreign_new = ensure_client(
        foreign_panel, foreign_ssh, foreign_inbound, foreign_email
    )
    if foreign_new:
        foreign_panel.restart_xray()

    uuid = foreign_client.get("id")
    if not uuid:
        raise VpnKitError(f"у клиента {foreign_email} нет UUID")

    # 2. Российский узел: панель, inbound, клиент, outbound, routing.
    print("\n--- российский узел ---")
    ru_panel = ensure_panel(ru_ssh, ru_ip)
    record_panel_creds(ru_alias, ru_ssh, panels_file)
    ru_inbound = ensure_inbound(ru_panel, ru_ssh, ru_ip, "ru")
    ru_email = ru_client_email(foreign_alias)
    _, ru_inbound, ru_new = ensure_client(ru_panel, ru_ssh, ru_inbound, ru_email)

    tag = outbound_tag(foreign_alias)
    routing_changed = ensure_outbound_and_routing(
        ru_panel, ru_ssh, tag, ru_email, foreign_ip, foreign_inbound, uuid
    )
    if routing_changed or ru_new:
        step(f"[{ru_ssh.host}] перезапускаю Xray")
        ru_panel.restart_xray()
        ok(f"[{ru_ssh.host}] Xray перезапущен")

    verify_outbound(ru_panel, ru_ssh, tag, parse_alias(foreign_alias)[1])

    # 3. Ссылка и запись в vless.md.
    print("\n--- ссылка ---")
    links = ru_panel.client_links(ru_email)
    if not links:
        raise VpnKitError(f"панель не отдала ссылку для клиента {ru_email}")
    link = replace_link_label(links[0], label)

    action = write_vless_entry(vless_file, label, link)
    ok(f"{os.path.relpath(vless_file, os.getcwd())}: {action}")
    print(f"\n{link}\n")

    ru_ssh.close()
    foreign_ssh.close()
    return link


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Собрать двухузловую VLESS-связку: российский узел → зарубежный",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("alias_ru", help="алиас российского узла, например timeweb_ru")
    parser.add_argument("alias_foreign", help="алиас зарубежного узла, например selectel_kz")
    parser.add_argument(
        "--vless-file",
        default=DEFAULT_VLESS_FILE,
        help=f"куда дописывать ссылку (по умолчанию {DEFAULT_VLESS_FILE})",
    )
    parser.add_argument(
        "--panels-file",
        default=DEFAULT_PANELS_FILE,
        help=f"куда дописывать доступы к панелям (по умолчанию {DEFAULT_PANELS_FILE})",
    )
    args = parser.parse_args()

    try:
        build_route(args.alias_ru, args.alias_foreign, args.vless_file, args.panels_file)
        return 0
    except VpnKitError as exc:
        fail(str(exc))
        return 1
    except KeyboardInterrupt:
        fail("прервано")
        return 130


if __name__ == "__main__":
    sys.exit(main())
