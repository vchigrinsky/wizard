#!/usr/bin/env python3
"""Слепок узла: что на нём настроено прямо сейчас. Только чтение.

    python scripts/vpn_snapshot_node.py beget_ru ishosting_kz
    python scripts/vpn_snapshot_node.py --all --save до.json
    python scripts/vpn_snapshot_node.py --all --diff до.json

Зачем. На части узлов живёт инфраструктура, которую трогать нельзя. Прежде чем
что-то на них досоздавать, нужно зафиксировать исходное состояние — иначе потом
нечем доказать, что существующее не пострадало. Скрипт снимает inbound'ы с их
клиентами, outbound'ы и правила маршрутизации, версии ядра и панели, и умеет
сравнить два слепка, показав ровно то, что изменилось.

Ничего не создаёт, не правит и не перезапускает.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpnkit import (  # noqa: E402
    Panel,
    Ssh,
    VpnKitError,
    fail,
    ok,
    parse_alias,
    parse_ssh_config,
    resolve_host,
    warn,
)


def as_dict(value) -> dict:
    if isinstance(value, str):
        return json.loads(value) if value.strip() else {}
    return value or {}


def snapshot(alias: str) -> dict:
    host, ip = resolve_host(alias)
    ssh = Ssh(host)
    if not ssh.alive():
        raise VpnKitError(f"нет доступа по ключу к {host}")

    panel = Panel(ssh)
    if not panel.installed():
        ssh.close()
        raise VpnKitError(f"[{host}] панели 3x-ui на узле нет")

    data: dict = {"alias": alias, "ip": ip, "xray": panel.xray_version(), "inbounds": {}}

    for inbound in panel.inbounds():
        clients = as_dict(inbound.get("settings")).get("clients", [])
        reality = as_dict(inbound.get("streamSettings")).get("realitySettings", {})
        data["inbounds"][inbound.get("remark") or f"#{inbound.get('id')}"] = {
            "id": inbound.get("id"),
            "port": inbound.get("port"),
            "protocol": inbound.get("protocol"),
            "enable": inbound.get("enable"),
            "serverNames": reality.get("serverNames"),
            # UUID нужен: если он поменяется, у людей отвалятся ключи
            "clients": {c.get("email"): c.get("id") for c in clients},
        }

    setting = panel.xray_setting()
    data["outbounds"] = {
        o.get("tag"): {
            "protocol": o.get("protocol"),
            "address": as_dict(o.get("settings")).get("address"),
            "port": as_dict(o.get("settings")).get("port"),
            "id": as_dict(o.get("settings")).get("id"),
        }
        for o in setting.get("outbounds", [])
    }
    data["rules"] = [
        {"user": r.get("user"), "outboundTag": r.get("outboundTag"),
         "domain": r.get("domain"), "ip": r.get("ip"), "port": r.get("port"),
         "inboundTag": r.get("inboundTag"), "network": r.get("network")}
        for r in setting.get("routing", {}).get("rules", [])
    ]
    ssh.close()
    return data


def show(data: dict) -> None:
    print(f"\n=== {data['alias']}  ({data['ip']})   xray {data['xray']}")
    for remark, inb in data["inbounds"].items():
        names = ", ".join(inb.get("serverNames") or []) or "—"
        print(f"  inbound '{remark}'  id={inb['id']} порт {inb['port']} "
              f"{inb['protocol']} sni={names}")
        for email in sorted(inb["clients"]):
            print(f"      клиент {email}")
    if data["outbounds"]:
        print("  outbounds:")
        for tag, o in data["outbounds"].items():
            addr = f"{o['address']}:{o['port']}" if o.get("address") else o.get("protocol")
            print(f"      {tag:28} {addr}")
    if data["rules"]:
        print("  правила маршрутизации:")
        for r in data["rules"]:
            who = ", ".join(r.get("user") or []) or (r.get("inboundTag") and "inbound") or "—"
            print(f"      {who:34} → {r.get('outboundTag')}")


def diff(before: dict, after: dict) -> list[str]:
    """Что изменилось. Добавления помечаем отдельно от правок и удалений:
    добавлять нам можно, а трогать существующее — нет."""
    out = []
    tag = before["alias"]

    if before.get("xray") != after.get("xray"):
        out.append(f"[{tag}] ИЗМЕНЕНО ядро Xray: {before.get('xray')} → {after.get('xray')}")

    for remark, old in before["inbounds"].items():
        new = after["inbounds"].get(remark)
        if new is None:
            out.append(f"[{tag}] УДАЛЁН inbound '{remark}'")
            continue
        for field in ("id", "port", "protocol", "enable", "serverNames"):
            if old.get(field) != new.get(field):
                out.append(
                    f"[{tag}] ИЗМЕНЁН inbound '{remark}'.{field}: "
                    f"{old.get(field)} → {new.get(field)}"
                )
        for email, uuid in old["clients"].items():
            if email not in new["clients"]:
                out.append(f"[{tag}] УДАЛЁН клиент {email} из '{remark}'")
            elif new["clients"][email] != uuid:
                out.append(f"[{tag}] ИЗМЕНЁН UUID клиента {email} в '{remark}'")
        for email in new["clients"]:
            if email not in old["clients"]:
                out.append(f"[{tag}] добавлен клиент {email} в '{remark}'")

    for remark in after["inbounds"]:
        if remark not in before["inbounds"]:
            out.append(f"[{tag}] добавлен inbound '{remark}'")

    for t, old in before["outbounds"].items():
        new = after["outbounds"].get(t)
        if new is None:
            out.append(f"[{tag}] УДАЛЁН outbound {t}")
        elif new != old:
            out.append(f"[{tag}] ИЗМЕНЁН outbound {t}: {old} → {new}")
    for t in after["outbounds"]:
        if t not in before["outbounds"]:
            out.append(f"[{tag}] добавлен outbound {t}")

    old_rules = [json.dumps(r, sort_keys=True, ensure_ascii=False) for r in before["rules"]]
    new_rules = [json.dumps(r, sort_keys=True, ensure_ascii=False) for r in after["rules"]]
    for r in old_rules:
        if r not in new_rules:
            out.append(f"[{tag}] УДАЛЕНО/ИЗМЕНЕНО правило: {r}")
    for r in new_rules:
        if r not in old_rules:
            out.append(f"[{tag}] добавлено правило: {r}")
    return out


def all_aliases() -> list[str]:
    found = set()
    for host in parse_ssh_config():
        alias = host.rsplit("_", 1)[0]
        try:
            parse_alias(alias)
        except VpnKitError:
            continue
        found.add(alias)
    return sorted(found)


def main() -> int:
    parser = argparse.ArgumentParser(description="Слепок настроек узла (только чтение)")
    parser.add_argument("aliases", nargs="*")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", help="записать слепок в JSON")
    parser.add_argument("--diff", help="сравнить с ранее сохранённым JSON")
    args = parser.parse_args()

    aliases = all_aliases() if args.all else args.aliases
    if not aliases:
        parser.error("укажите алиасы или --all")

    collected, failed = {}, []
    for alias in aliases:
        try:
            collected[alias] = snapshot(alias)
        except VpnKitError as exc:
            warn(f"[{alias}] {exc}")
            failed.append(alias)

    if args.diff:
        with open(args.diff, encoding="utf-8") as fh:
            before = json.load(fh)
        problems, additions = [], []
        for alias, after in collected.items():
            if alias not in before:
                additions.append(f"[{alias}] узел не было в исходном слепке")
                continue
            for line in diff(before[alias], after):
                (problems if any(w in line for w in ("УДАЛ", "ИЗМЕН")) else additions).append(line)
        for alias in before:
            if alias not in collected:
                problems.append(f"[{alias}] узел пропал из слепка (не опрошен)")

        print("\n--- добавления (это нам можно) ---")
        for line in additions or ["  ничего"]:
            print(f"  {line}")
        print("\n--- правки существующего (этого быть не должно) ---")
        if problems:
            for line in problems:
                fail(f"  {line}")
            return 1
        ok("  ничего не тронуто")
        return 0

    for alias in aliases:
        if alias in collected:
            show(collected[alias])

    if args.save:
        with open(args.save, "w", encoding="utf-8") as fh:
            json.dump(collected, fh, ensure_ascii=False, indent=2)
        ok(f"\nслепок сохранён: {args.save}")

    if failed:
        warn(f"не опрошены: {', '.join(failed)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
