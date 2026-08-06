#!/usr/bin/env python3
"""Прямые клиенты: подключение к зарубежному узлу без российского хопа.

    python scripts/vpn_direct.py timeweb_nl bigvds_nl        # выбранные узлы
    python scripts/vpn_direct.py --all                       # все зарубежные из ~/.ssh/config
    python scripts/vpn_direct.py --all --drop                # снять прямых клиентов

Зачем это нужно. Основная схема — двухузловая: клиент идёт на российский
узел, тот через Reality уходит за границу. У неё есть достоинство (внутри
страны трафик выглядит внутристрановым), но для изучения фильтрации она
неудобна: между нами и зарубежным сервером стоит наш же российский узел, и
непонятно, где именно рвётся — на пути «мы → РФ-узел» или «РФ-узел → заграница».

Прямой клиент убирает посредника: мы из российской сети ходим прямо на
зарубежный IP по VLESS+Reality на 443. Это ровно тот сценарий, по которому
работает фильтрация трансграничного трафика, поэтому такая связка — самый
чистый инструмент, чтобы поймать её поведение.

Клиент заводится в том же inbound'е ``main``, что и обычные, под отдельной
почтой, поэтому не мешает существующим маршрутам и снимается одной командой.
Ссылки складываются в отдельный файл ``direct.md`` — в vless.md им не место,
там production-маршруты.
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_build_route import (  # noqa: E402
    ensure_client,
    ensure_inbound,
    ensure_panel,
    find_client,
    record_panel_creds,
    write_vless_entry,
)
from vpnkit import (  # noqa: E402
    INBOUND_REMARK,
    Panel,
    Ssh,
    VpnKitError,
    fail,
    flag,
    ok,
    panel_sort_key,
    parse_alias,
    parse_ssh_config,
    replace_link_label,
    resolve_host,
    sort_file,
    step,
    warn,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DIRECT_FILE = os.path.join(REPO_ROOT, "direct.md")
DEFAULT_PANELS_FILE = os.path.join(REPO_ROOT, "panels.md")

#: Почта прямого клиента. Отдельная от `main-from-*`, чтобы прямые
#: подключения было видно в статистике панели отдельной строкой.
DIRECT_CLIENT_EMAIL = "vvchigrinskii-direct"

#: Узлы, которые трогать запрещено: на них живая инфраструктура с клиентами.
FORBIDDEN = ("beget_ru", "ishosting_kz", "ishosting_nl", "ishosting_us")


def direct_label(alias: str) -> str:
    """``bigvds_nl`` -> ``🇳🇱 bigvds ← 🏠 напрямую``."""
    hosting, country = parse_alias(alias)
    return f"{flag(country)} {hosting} ← 🏠 напрямую"


def sort_direct_file(path: str) -> bool:
    """Порядок как в panels.md — по хостингу, внутри по стране."""
    return sort_file(path, lambda header: panel_sort_key(header.split("←")[0].rstrip()))


def foreign_aliases() -> list[str]:
    """Все зарубежные узлы из ~/.ssh/config, кроме запрещённых."""
    found = set()
    for host in parse_ssh_config():
        alias = host.rsplit("_", 1)[0]  # bigvds_nl_109.104.153.242 -> bigvds_nl
        try:
            _, country = parse_alias(alias)
        except VpnKitError:
            continue
        if country != "ru" and alias not in FORBIDDEN:
            found.add(alias)
    return sorted(found)


def add_direct(alias: str, direct_file: str, panels_file: str) -> str:
    host, ip = resolve_host(alias)
    label = direct_label(alias)
    print(f"\n=== {label} ===")
    print(f"    {host} ({ip})\n")

    ssh = Ssh(host)
    if not ssh.alive():
        raise VpnKitError(f"нет доступа по ключу к {host}; проверьте: ssh {host}")

    panel = ensure_panel(ssh, ip)
    record_panel_creds(alias, ssh, panels_file)
    inbound = ensure_inbound(panel, ssh, ip, "foreign")
    _, inbound, created = ensure_client(panel, ssh, inbound, DIRECT_CLIENT_EMAIL)
    if created:
        panel.restart_xray()

    links = panel.client_links(DIRECT_CLIENT_EMAIL)
    if not links:
        raise VpnKitError(f"[{host}] панель не отдала ссылку для {DIRECT_CLIENT_EMAIL}")

    action = write_vless_entry(direct_file, label, replace_link_label(links[0], label))
    if sort_direct_file(direct_file):
        action += ", отсортирован"
    ok(f"[{host}] {os.path.basename(direct_file)}: {action}")
    ssh.close()
    return action


def drop_direct(alias: str, direct_file: str) -> None:
    host, _ = resolve_host(alias)
    label = direct_label(alias)
    print(f"\n=== {label} ===")

    ssh = Ssh(host)
    if not ssh.alive():
        raise VpnKitError(f"нет доступа по ключу к {host}")

    panel = Panel(ssh)
    inbound = panel.find_inbound(INBOUND_REMARK)
    if inbound and find_client(inbound, DIRECT_CLIENT_EMAIL):
        step(f"[{host}] снимаю клиента {DIRECT_CLIENT_EMAIL}")
        panel.post_empty(f"/panel/api/clients/del/{DIRECT_CLIENT_EMAIL}")
        panel.restart_xray()
        ok(f"[{host}] клиент снят")
    else:
        ok(f"[{host}] прямого клиента и не было")

    remove_direct_entry(direct_file, label)
    ssh.close()


def remove_direct_entry(path: str, label: str) -> None:
    """Убирает секцию узла из direct.md, если она там есть."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().splitlines()

    out, skipping = [], False
    for line in lines:
        if line.startswith("## "):
            skipping = label in line
        if not skipping:
            out.append(line)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out).rstrip("\n") + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Прямые клиенты на зарубежных узлах (без российского хопа)"
    )
    parser.add_argument("aliases", nargs="*", help="алиасы зарубежных узлов")
    parser.add_argument("--all", action="store_true", help="все зарубежные узлы из ~/.ssh/config")
    parser.add_argument("--drop", action="store_true", help="снять прямых клиентов")
    parser.add_argument("--direct-file", default=DEFAULT_DIRECT_FILE)
    parser.add_argument("--panels-file", default=DEFAULT_PANELS_FILE)
    args = parser.parse_args()

    aliases = foreign_aliases() if args.all else args.aliases
    if not aliases:
        parser.error("укажите алиасы или --all")

    forbidden = [a for a in aliases if a in FORBIDDEN]
    if forbidden:
        fail(f"эти узлы трогать нельзя: {', '.join(forbidden)}")
        return 2

    print(f"узлов в работе: {len(aliases)} — {', '.join(aliases)}")
    failures = []
    for alias in aliases:
        try:
            if args.drop:
                drop_direct(alias, args.direct_file)
            else:
                add_direct(alias, args.direct_file, args.panels_file)
        except VpnKitError as exc:
            warn(f"[{alias}] {exc}")
            failures.append(alias)

    print()
    if failures:
        fail(f"не получилось: {', '.join(failures)}")
        return 1
    ok("все узлы обработаны")
    return 0


if __name__ == "__main__":
    sys.exit(main())
