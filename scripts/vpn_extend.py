#!/usr/bin/env python3
"""Дособрать маршруты на узлах, где уже живёт чужая инфраструктура.

    python scripts/vpn_extend.py --plan          # показать, что будет сделано
    python scripts/vpn_extend.py --apply

Чем отличается от vpn_build_route.py
------------------------------------

Обычный сборщик рассчитан на узел, которым мы распоряжаемся целиком: он при
необходимости доустановит 3x-ui и приведёт ядро Xray к версии из констант. На
``beget_ru`` и ``ishosting_*`` так делать нельзя — там работают живые клиенты,
а на ``ishosting_kz`` ядро вообще новее нашего, и обычный сборщик откатил бы
его назад.

Поэтому здесь всё только на добавление. Скрипт:

* никогда не ставит и не обновляет ни панель, ни Xray;
* никогда не создаёт inbound — если ``main`` нет, это ошибка, а не повод его
  завести;
* заводит только тех клиентов, которых ещё нет;
* отказывается трогать outbound или правило, если тег уже занят;
* перезапускает Xray один раз на узел, а не после каждой мелочи.

Перезапуск всё же нужен: без него панель не начнёт отдавать трафик новым
клиентам. Он занимает секунду-две, но существующие соединения на это время
рвутся — поэтому узлы с живыми людьми обрабатываются последними.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpn_build_route import (  # noqa: E402
    as_dict,
    build_outbound,
    find_client,
    write_vless_entry,
)
from vpn_direct import DIRECT_CLIENT_EMAIL, direct_label, sort_direct_file  # noqa: E402
from vpnkit import (  # noqa: E402
    INBOUND_REMARK,
    Panel,
    Ssh,
    VpnKitError,
    fail,
    foreign_client_email,
    ok,
    outbound_tag,
    parse_alias,
    replace_link_label,
    resolve_host,
    route_label,
    ru_client_email,
    step,
    warn,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_VLESS_FILE = os.path.join(REPO_ROOT, "vless.md")
DEFAULT_DIRECT_FILE = os.path.join(REPO_ROOT, "direct.md")

#: Двухузловые связки, которых не хватало. Слева российский узел, справа
#: зарубежный.
#:
#: ishosting_us особенный: его адрес не пускают из российских сетей, поэтому
#: напрямую по SSH он недоступен, а заходить на него надо транзитом через узел,
#: которому он открыт::
#:
#:     ssh -o ProxyJump=beget_ru_84.54.28.195 ishosting_us_38.180.135.5
#:
#: На время сборки в ~/.ssh/config добавляется строка ``ProxyJump``, после —
#: убирается. Сам маршрут при этом работает: недоступен только вход снаружи.
ROUTES: list[tuple[str, str]] = [
    ("beget_ru", "timeweb_nl"),
    ("beget_ru", "selectel_kz"),
    ("beget_ru", "selectel_uz"),
    ("beget_ru", "vpsville_nl"),
    ("beget_ru", "bigvds_nl"),
    ("timeweb_ru", "ishosting_kz"),
    ("timeweb_ru", "ishosting_nl"),
    ("timeweb_ru", "ishosting_us"),
    ("selectel_ru", "ishosting_kz"),
    ("selectel_ru", "ishosting_nl"),
    ("selectel_ru", "ishosting_us"),
    ("vpsville_ru", "ishosting_kz"),
    ("vpsville_ru", "ishosting_nl"),
    ("vpsville_ru", "ishosting_us"),
]

#: Узлы, на которых нужен прямой клиент — вход без промежуточного хопа.
DIRECTS: list[str] = ["beget_ru", "ishosting_kz", "ishosting_nl", "ishosting_us"]

#: Обрабатываются последними: на них живые пользователи и наш собственный
#: прокси, поэтому перезапуск Xray там — самое чувствительное место.
LAST: tuple[str, ...] = ("ishosting_kz", "beget_ru")


class Node:
    """Открытый узел: ssh, панель и найденный inbound ``main``."""

    def __init__(self, alias: str):
        self.alias = alias
        self.host, self.ip = resolve_host(alias)
        self.ssh = Ssh(self.host)
        if not self.ssh.alive():
            raise VpnKitError(f"нет доступа по ключу к {self.host}")

        self.panel = Panel(self.ssh)
        if not self.panel.installed():
            raise VpnKitError(
                f"[{self.host}] панели 3x-ui нет. Ставить её здесь запрещено — "
                f"разберитесь руками"
            )
        self.xray = self.panel.xray_version()
        self.inbound = self.panel.find_inbound(INBOUND_REMARK)
        if not self.inbound:
            raise VpnKitError(
                f"[{self.host}] нет inbound'а '{INBOUND_REMARK}'. Создавать его "
                f"здесь запрещено"
            )
        self.dirty = False

    def clients(self) -> dict[str, str]:
        return {
            c.get("email"): c.get("id")
            for c in as_dict(self.inbound.get("settings")).get("clients", [])
        }

    def add_client(self, email: str) -> bool:
        """True, если клиента завели; False — если он уже был."""
        if find_client(self.inbound, email):
            ok(f"[{self.host}] клиент {email} уже есть")
            return False
        step(f"[{self.host}] добавляю клиента {email}")
        self.panel.add_client(email, self.inbound["id"])
        self.inbound = self.panel.find_inbound(INBOUND_REMARK) or self.inbound
        if not find_client(self.inbound, email):
            raise VpnKitError(f"[{self.host}] клиент {email} не появился в inbound'е")
        self.dirty = True
        return True

    def add_outbound_and_rule(
        self, tag: str, client_email: str, foreign_ip: str, foreign_inbound: dict, uuid: str
    ) -> None:
        setting = self.panel.xray_setting()
        outbounds = setting.setdefault("outbounds", [])
        rules = setting.setdefault("routing", {}).setdefault("rules", [])
        changed = False

        if any(o.get("tag") == tag for o in outbounds):
            # Намеренно не чиним и не переписываем: на этих узлах чужой
            # outbound с таким тегом может обслуживать живых людей.
            ok(f"[{self.host}] outbound {tag} уже есть — не трогаю")
        else:
            step(f"[{self.host}] добавляю outbound {tag}")
            outbounds.append(build_outbound(tag, foreign_ip, foreign_inbound, uuid))
            changed = True

        if any(
            r.get("outboundTag") == tag and client_email in (r.get("user") or [])
            for r in rules
        ):
            ok(f"[{self.host}] правило {client_email} → {tag} уже есть")
        else:
            step(f"[{self.host}] добавляю правило {client_email} → {tag}")
            rules.append(
                {"type": "field", "enabled": True, "user": [client_email], "outboundTag": tag}
            )
            changed = True

        if changed:
            self.panel.save_xray_setting(setting)
            self.dirty = True

    def restart_if_needed(self) -> None:
        if not self.dirty:
            ok(f"[{self.host}] изменений нет, перезапуск не нужен")
            return
        step(f"[{self.host}] перезапускаю Xray (короткий разрыв соединений)")
        self.panel.restart_xray()
        self.inbound = self.panel.find_inbound(INBOUND_REMARK) or self.inbound
        ok(f"[{self.host}] Xray перезапущен")

    def close(self) -> None:
        self.ssh.close()


def node_order(aliases) -> list[str]:
    """Чувствительные узлы — в конец."""
    return sorted(aliases, key=lambda a: (a in LAST, LAST.index(a) if a in LAST else 0, a))


def plan(
    routes: list[tuple[str, str]] | None = None, directs: list[str] | None = None
) -> tuple[dict[str, list[str]], dict[str, list[tuple]]]:
    """Что и куда нужно добавить. Ключ — алиас узла."""
    routes = ROUTES if routes is None else routes
    directs = DIRECTS if directs is None else directs
    need_clients: dict[str, list[str]] = {}
    need_routes: dict[str, list[tuple]] = {}

    for ru, foreign in routes:
        need_clients.setdefault(foreign, []).append(foreign_client_email(ru))
        email = ru_client_email(foreign)
        need_clients.setdefault(ru, []).append(email)
        need_routes.setdefault(ru, []).append((foreign, email, outbound_tag(foreign)))

    for alias in directs:
        need_clients.setdefault(alias, []).append(DIRECT_CLIENT_EMAIL)

    return need_clients, need_routes


def show_plan(routes: list[tuple[str, str]], directs: list[str]) -> None:
    need_clients, need_routes = plan(routes, directs)
    print("Будет добавлено (существующее не трогаем):\n")
    for alias in node_order(need_clients):
        print(f"  {alias}")
        for email in sorted(set(need_clients[alias])):
            kind = "прямой вход" if email == DIRECT_CLIENT_EMAIL else "клиент"
            print(f"      {kind:14} {email}")
        for foreign, email, tag in sorted(need_routes.get(alias, [])):
            print(f"      outbound+правило {tag}  ({email} → {foreign})")
    print(f"\nвсего связок: {len(routes)}, прямых клиентов: {len(directs)}")
    print("перезапусков Xray: по одному на узел, чувствительные — последними")


def apply(vless_file: str, direct_file: str, routes: list[tuple[str, str]],
          directs: list[str]) -> int:
    need_clients, need_routes = plan(routes, directs)
    nodes: dict[str, Node] = {}
    failures: list[str] = []
    #: связки, у которых собрано всё: клиент, outbound и правило
    wired: set[tuple[str, str]] = set()

    def node(alias: str) -> Node:
        if alias not in nodes:
            nodes[alias] = Node(alias)
            n = nodes[alias]
            print(f"\n=== {alias}  {n.host} ({n.ip})   xray {n.xray}")
        return nodes[alias]

    # --- 1. Клиенты на зарубежных узлах: их UUID нужны для outbound'ов.
    print("\n########## клиенты на приёмных узлах ##########")
    targets = {f for _, f in routes} | set(directs)
    for alias in node_order(targets):
        try:
            n = node(alias)
            for email in sorted(set(need_clients.get(alias, []))):
                # На узле, который сам является российским хопом, клиенты
                # вида vvchigrinskii-to-* заводим на втором шаге — вместе с
                # их правилами, чтобы не перезапускать Xray дважды.
                if email.startswith("vvchigrinskii-to-"):
                    continue
                n.add_client(email)
        except VpnKitError as exc:
            warn(f"[{alias}] {exc}")
            failures.append(alias)

    for alias in node_order(targets):
        if alias in nodes and alias not in need_routes:
            nodes[alias].restart_if_needed()

    # --- 2. Российские узлы: клиенты, outbound'ы, правила, один перезапуск.
    print("\n########## российские узлы ##########")
    for alias in node_order(need_routes):
        if alias in failures:
            continue
        try:
            n = node(alias)
            for email in sorted(set(need_clients.get(alias, []))):
                n.add_client(email)

            for foreign, email, tag in sorted(need_routes[alias]):
                if foreign in failures or foreign not in nodes:
                    warn(f"[{alias}] пропускаю {tag}: приёмный узел {foreign} недоступен")
                    continue
                fn = nodes[foreign]
                uuid = fn.clients().get(foreign_client_email(alias))
                if not uuid:
                    warn(f"[{alias}] у {foreign} нет UUID для {foreign_client_email(alias)}")
                    continue
                n.add_outbound_and_rule(tag, email, fn.ip, fn.inbound, uuid)
                # Ссылку выдаём только для полностью собранной связки. Без
                # outbound'а клиент существует, но уходит в маршрут по
                # умолчанию — то есть ссылка врала бы про страну выхода.
                wired.add((alias, foreign))

            n.restart_if_needed()
        except VpnKitError as exc:
            warn(f"[{alias}] {exc}")
            failures.append(alias)

    # --- 3. Ссылки.
    print("\n########## ссылки ##########")
    for ru, foreign in routes:
        if (ru, foreign) not in wired:
            warn(f"{route_label(foreign, ru)}: связка не собрана, ссылку не пишу")
            continue
        label = route_label(foreign, ru)
        email = ru_client_email(foreign)
        try:
            links = nodes[ru].panel.client_links(email)
            if not links:
                warn(f"[{ru}] панель не отдала ссылку для {email}")
                continue
            action = write_vless_entry(vless_file, label, replace_link_label(links[0], label))
            ok(f"{label}: {action}")
        except VpnKitError as exc:
            warn(f"[{ru}] ссылка для {email}: {exc}")

    for alias in directs:
        if alias in failures or alias not in nodes:
            continue
        label = direct_label(alias)
        try:
            links = nodes[alias].panel.client_links(DIRECT_CLIENT_EMAIL)
            if not links:
                warn(f"[{alias}] панель не отдала прямую ссылку")
                continue
            action = write_vless_entry(direct_file, label, replace_link_label(links[0], label))
            if sort_direct_file(direct_file):
                action += ", отсортирован"
            ok(f"{label}: {action}")
        except VpnKitError as exc:
            warn(f"[{alias}] прямая ссылка: {exc}")

    for n in nodes.values():
        n.close()

    print()
    if failures:
        fail(f"с ошибками: {', '.join(sorted(set(failures)))}")
        return 1
    ok("всё добавлено")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Добавить недостающие маршруты на узлы с живой инфраструктурой"
    )
    parser.add_argument("--plan", action="store_true", help="показать план и выйти")
    parser.add_argument("--apply", action="store_true", help="выполнить")
    parser.add_argument("--vless-file", default=DEFAULT_VLESS_FILE)
    parser.add_argument("--direct-file", default=DEFAULT_DIRECT_FILE)
    parser.add_argument(
        "--route", action="append", metavar="RU:FOREIGN",
        help="связка вместо списка по умолчанию, можно несколько раз",
    )
    parser.add_argument(
        "--direct", action="append", metavar="ALIAS",
        help="узел для прямого клиента вместо списка по умолчанию",
    )
    args = parser.parse_args()

    if args.route or args.direct:
        routes = [tuple(r.split(":", 1)) for r in (args.route or [])]
        directs = args.direct or []
    else:
        routes, directs = ROUTES, DIRECTS

    if not args.apply:
        show_plan(routes, directs)
        return 0
    try:
        return apply(args.vless_file, args.direct_file, routes, directs)
    except KeyboardInterrupt:
        fail("прервано")
        return 130


if __name__ == "__main__":
    sys.exit(main())
