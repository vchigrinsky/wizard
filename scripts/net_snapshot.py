#!/usr/bin/env python3
"""Снимок сети: один и тот же набор проб, чтобы сети можно было сравнивать.

    python3 scripts/net_snapshot.py lovitel
    python3 scripts/net_snapshot.py mts-hotspot

Зачем отдельная обёртка. Сравнивать две сети можно только тогда, когда в них
прогнали ровно одно и то же. Стоит один раз запустить чуть другой набор
флагов — и разница в результатах окажется разницей в методике, а не в сетях.
Поэтому весь набор зашит здесь, а снаружи задаётся только название точки.

Что делает:

* записывает, где мы находимся — адрес выхода, оператора, шлюз, резолверы;
* прогоняет все маршруты из ``vless.md`` и ``direct.md`` настоящими
  туннелями, с нагрузкой;
* прогоняет батарею проб ``blackout_probe`` — DNS, сайты, маяки, подмена
  имени, объём.

Всё складывается в один файл в ``snapshots/``, оттуда потом и сравниваем.

Важно: маршруты проверяются **копиями** файлов, поэтому отметки ✅/❌ в
рабочих ``vless.md`` и ``direct.md`` не трогаются.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
SNAPSHOT_DIR = os.path.join(REPO_ROOT, "snapshots")

#: Маяки — узлы, на которых стоит blackout_beacon.py.
BEACONS = ["185.11.134.248", "72.56.236.30", "109.104.153.242", "185.220.35.18"]

#: Нагрузка намеренно небольшая: снимок должен укладываться в пару минут,
#: иначе сеть успеет измениться прямо во время замера.
TRAFFIC_MB = "8"
STREAMS = "2"


def run(cmd: list[str], timeout: int = 900) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              cwd=REPO_ROOT)
        return (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return "(не уложилось в отведённое время)"
    except OSError as exc:
        return f"(не запустилось: {exc})"


def system_tunnel_up() -> str | None:
    """Если поднят системный ВПН, замер бессмыслен: мы измерим туннель.

    Возвращает имя интерфейса, если маршрут по умолчанию ведёт в туннель.
    """
    out = run(["route", "-n", "get", "default"], timeout=15)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            name = line.split(":", 1)[1].strip()
            return name if name.startswith(("utun", "ppp", "ipsec")) else None
    return None


def where_am_i() -> str:
    parts = []
    egress = run(["curl", "-sS", "--max-time", "15", "https://ipwho.is/"], timeout=25)
    try:
        data = json.loads(egress)
        conn = data.get("connection") or {}
        parts.append(f"выход:     {data.get('ip')} — {data.get('country')}, "
                     f"{data.get('city')}, AS{conn.get('asn')} {conn.get('isp')}")
    except ValueError:
        parts.append(f"выход:     не определился ({egress[:80]})")

    gateway = run(["route", "-n", "get", "default"], timeout=15)
    for line in gateway.splitlines():
        if "gateway:" in line or "interface:" in line:
            parts.append("           " + " ".join(line.split()))

    dns = run(["scutil", "--dns"], timeout=15)
    servers = []
    for line in dns.splitlines():
        if "nameserver[0]" in line:
            value = line.split(":", 1)[1].strip()
            if value not in servers:
                servers.append(value)
    parts.append(f"резолверы: {', '.join(servers) or 'не определились'}")

    wifi = run(["networksetup", "-getairportnetwork", "en0"], timeout=15)
    parts.append(f"сеть:      {wifi.splitlines()[0] if wifi else '?'}")
    return "\n".join(parts)


def check_routes(source: str, workdir: str) -> str:
    """Прогон маршрутов по копии файла — рабочий не трогаем."""
    path = os.path.join(REPO_ROOT, source)
    if not os.path.exists(path):
        return f"(файла {source} нет)"
    copy = os.path.join(workdir, source)
    shutil.copy(path, copy)
    # Снимаем прошлые отметки, иначе скрипт пропустит уже размеченное.
    with open(copy, encoding="utf-8") as fh:
        text = fh.read()
    for mark in (" ✅", " ❌"):
        text = text.replace(mark, "")
    with open(copy, "w", encoding="utf-8") as fh:
        fh.write(text)

    return run([sys.executable, os.path.join(HERE, "vpn_check_routes.py"), copy,
                "--recheck", "--traffic-mb", TRAFFIC_MB, "--streams", STREAMS])


def main() -> int:
    parser = argparse.ArgumentParser(description="Одинаковый снимок сети для сравнения")
    parser.add_argument("label", help="название точки: lovitel, mts-hotspot, ...")
    parser.add_argument("--skip-routes", action="store_true",
                        help="без прогона маршрутов (быстрее)")
    parser.add_argument("--allow-system-vpn", action="store_true")
    args = parser.parse_args()

    tunnel = system_tunnel_up()
    if tunnel and not args.allow_system_vpn:
        print(f"поднят системный туннель ({tunnel}) — замер измерил бы его, а не сеть.\n"
              f"выключите ВПН и повторите (или --allow-system-vpn, если так и задумано)",
              file=sys.stderr)
        return 2

    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = os.path.join(SNAPSHOT_DIR, f"{args.label}-{stamp}.md")
    raw_path = os.path.join(SNAPSHOT_DIR, f"{args.label}-{stamp}.jsonl")

    sections: list[tuple[str, str]] = []

    print(f"снимок «{args.label}» — где мы")
    sections.append(("Где мы", where_am_i()))

    if not args.skip_routes:
        for source in ("direct.md", "vless.md"):
            print(f"снимок «{args.label}» — маршруты из {source} (это долго)")
            with tempfile.TemporaryDirectory() as workdir:
                sections.append((f"Маршруты: {source}", check_routes(source, workdir)))

    print(f"снимок «{args.label}» — батарея проб")
    sections.append(("Пробы: DNS, сайты, маяки, подмена имени, объём", run(
        [sys.executable, os.path.join(HERE, "blackout_probe.py"),
         "--beacons", ",".join(BEACONS), "--once", "--out", raw_path])))

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(f"# Снимок сети: {args.label}\n\n")
        fh.write(f"Снят {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.\n")
        for title, body in sections:
            fh.write(f"\n## {title}\n\n```\n{body}\n```\n")

    print(f"\nготово: {report_path}")
    print(f"сырые события: {raw_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
