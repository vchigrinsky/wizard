#!/usr/bin/env python3
"""Сторож маршрутов: периодически проверяет все связки и ведёт журнал.

    python scripts/vpn_watch.py                 # один проход
    python scripts/vpn_watch.py --install-agent # проверять каждые 15 минут в фоне
    python scripts/vpn_watch.py --report        # что происходило за последнее время

Зачем нужен. Маршрут может отвалиться и через час починиться сам — и если в
этот момент никто не смотрел, причина уходит вместе с симптомом. Сторож
раз в четверть часа поднимает туннель по каждому маршруту, проверяет страну
выхода и дописывает строку в журнал. Когда что-то ломается снова, у нас
сразу есть: точное время начала, какие именно маршруты легли, а какие нет, и
чем это отличалось от предыдущего успешного прохода.

Журнал — TSV, по строке на проверку: время, метка маршрута, итог, детали.
Лежит в ~/Library/Logs/vpnkit-watch.tsv.
"""

from __future__ import annotations

import argparse
import datetime
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_check_routes import (  # noqa: E402
    GEO_PROVIDERS,
    LocalTunnel,
    find_xray,
    parse_vless_file,
    probe,
)
from vpnkit import VpnKitError, fail, ok, step  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_VLESS_FILE = os.path.join(REPO_ROOT, "vless.md")
LOG_PATH = os.path.expanduser("~/Library/Logs/vpnkit-watch.tsv")

AGENT_LABEL = "com.vuutya.vpn-watch"
AGENT_PLIST = os.path.expanduser(f"~/Library/LaunchAgents/{AGENT_LABEL}.plist")
INTERVAL_SECONDS = 900


def now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def egress() -> str:
    """Откуда мы сейчас видны — сеть меняется, и это важно для разбора."""
    proc = subprocess.run(
        ["curl", "-sS", "--max-time", "12", "https://ipwho.is/"],
        capture_output=True, text=True,
    )
    try:
        import json

        d = json.loads(proc.stdout)
        return f"{d.get('ip','?')}/{(d.get('connection') or {}).get('asn','?')}"
    except Exception:
        return "?"


def run_once(vless_file: str) -> int:
    xray = find_xray()
    _, routes = parse_vless_file(vless_file)
    where = egress()
    bad = 0

    with open(LOG_PATH, "a", encoding="utf-8") as log:
        for route in routes:
            expected = route.expected_country
            verdict, detail = "FAIL", ""
            try:
                with LocalTunnel(xray, route.link) as tunnel:
                    seen = [(n, c) for n, c in probe(GEO_PROVIDERS, tunnel.port) if c]
                detail = ",".join(f"{n}={c.upper()}" for n, c in seen) or "нет ответа"
                if seen and expected in {c for _, c in seen}:
                    verdict = "OK"
            except VpnKitError as exc:
                detail = str(exc)[:120].replace("\t", " ").replace("\n", " ")

            if verdict != "OK":
                bad += 1
            log.write(f"{now()}\t{where}\t{route.label}\t{verdict}\t{detail}\n")
            log.flush()
    return bad


def install_agent() -> None:
    python = sys.executable
    script = os.path.abspath(__file__)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>{script}</string>
    </array>
    <key>StartInterval</key><integer>{INTERVAL_SECONDS}</integer>
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>/tmp/vpnkit-watch.out</string>
    <key>StandardErrorPath</key><string>/tmp/vpnkit-watch.out</string>
</dict>
</plist>
"""
    os.makedirs(os.path.dirname(AGENT_PLIST), exist_ok=True)
    with open(AGENT_PLIST, "w", encoding="utf-8") as fh:
        fh.write(plist)
    subprocess.run(
        ["launchctl", "bootout", f"gui/{os.getuid()}/{AGENT_LABEL}"],
        capture_output=True, text=True,
    )
    proc = subprocess.run(
        ["launchctl", "bootstrap", f"gui/{os.getuid()}", AGENT_PLIST],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise VpnKitError(f"launchctl отказал: {proc.stderr.strip()}")
    ok(f"сторож установлен, проверка каждые {INTERVAL_SECONDS // 60} минут")
    print(f"    журнал: {LOG_PATH}")


def report() -> None:
    """Показывает переходы OK↔FAIL — то есть моменты, когда что-то менялось."""
    if not os.path.exists(LOG_PATH):
        raise VpnKitError(f"журнала ещё нет: {LOG_PATH}")
    last: dict[str, str] = {}
    changes = []
    with open(LOG_PATH, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                continue
            ts, where, label, verdict, detail = parts[:5]
            if label in last and last[label] != verdict:
                changes.append((ts, where, label, last[label], verdict, detail))
            last[label] = verdict
    print(f"переходов состояния: {len(changes)}\n")
    for ts, where, label, was, became, detail in changes[-40:]:
        print(f"  {ts}  {where:24} {label:32} {was} → {became}   {detail[:60]}")
    print("\nтекущее состояние:")
    for label, verdict in sorted(last.items()):
        print(f"  {verdict:5} {label}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Сторож маршрутов из vless.md")
    parser.add_argument("--vless-file", default=DEFAULT_VLESS_FILE)
    parser.add_argument("--install-agent", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    try:
        if args.install_agent:
            install_agent()
            return 0
        if args.report:
            report()
            return 0
        step("проверяю маршруты")
        bad = run_once(args.vless_file)
        (ok if bad == 0 else fail)(f"проход записан, проблемных маршрутов: {bad}")
        return 0
    except VpnKitError as exc:
        fail(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
