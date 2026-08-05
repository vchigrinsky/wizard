#!/usr/bin/env python3
"""Записать доступы к панели 3x-ui одного узла в panels.md.

    python scripts/vpn_panel_creds.py ALIAS

Например::

    python scripts/vpn_panel_creds.py timeweb_ru

Ходит на сервер, забирает из ``/etc/x-ui/install-result.env`` адрес панели,
логин и пароль и дописывает их в ``panels.md``. Если запись про этот узел там
уже есть — ничего не делает.

Инструмент атомарный: он только читает и записывает. Панель не ставит и не
настраивает — этим занимается vpn_build_route.py, который дёргает ту же
запись автоматически для обоих узлов связки.
"""

from __future__ import annotations

import argparse
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
    resolve_host,
    step,
    write_panel_entry,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PANELS_FILE = os.path.join(REPO_ROOT, "panels.md")


def record_panel(alias: str, panels_file: str, ssh: Ssh | None = None) -> str:
    """Записывает доступы к панели узла. Возвращает описание результата.

    Готовое SSH-соединение можно передать снаружи — так vpn_build_route.py
    переиспользует то, которое уже открыто, вместо второго подключения.
    """
    parse_alias(alias)
    host, ip = resolve_host(alias)

    own_connection = ssh is None
    if ssh is None:
        ssh = Ssh(host)

    try:
        panel = Panel(ssh)
        if not panel.installed():
            raise VpnKitError(
                f"[{host}] 3x-ui не установлена — сначала соберите связку "
                "через vpn_build_route.py"
            )
        creds = panel.credentials(ip=ip)
        return write_panel_entry(panels_file, alias, creds)
    finally:
        if own_connection:
            ssh.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Записать URL, логин и пароль панели 3x-ui в panels.md",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("alias", help="алиас узла, например timeweb_ru")
    parser.add_argument(
        "--panels-file",
        default=DEFAULT_PANELS_FILE,
        help=f"куда записывать (по умолчанию {DEFAULT_PANELS_FILE})",
    )
    args = parser.parse_args()

    try:
        step(f"забираю доступы к панели {args.alias}")
        action = record_panel(args.alias, args.panels_file)
        ok(f"{os.path.relpath(args.panels_file, os.getcwd())}: {action}")
        return 0
    except VpnKitError as exc:
        fail(str(exc))
        return 1
    except KeyboardInterrupt:
        fail("прервано")
        return 130


if __name__ == "__main__":
    sys.exit(main())
