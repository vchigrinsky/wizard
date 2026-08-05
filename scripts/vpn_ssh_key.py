#!/usr/bin/env python3
"""Шаг 0: завести SSH-ключ под только что арендованный сервер.

    python scripts/vpn_ssh_key.py ALIAS IP PASSWORD [USER]

Например::

    python scripts/vpn_ssh_key.py ishosting_kz 38.180.207.211 'пароль_от_root'
    python scripts/vpn_ssh_key.py bigvds_nl 109.104.153.242 'пароль' ubuntu

Что делает:

1. создаёт ключ ``~/.ssh/id_ed25519_vps_<ALIAS>_<IP>`` без парольной фразы;
2. кладёт публичную половину в ``~/.ssh/authorized_keys`` на сервере, зайдя
   туда по паролю;
3. дописывает блок ``Host <ALIAS>_<IP>`` в ``~/.ssh/config``;
4. проверяет, что вход по ключу работает.

Скрипт идемпотентен: существующий ключ не перезаписывается, повторный запуск
просто досогласует то, чего не хватает. Пароль нужен ровно один раз — дальше
всё ходит по ключу.

Зависимостей нет, парольная аутентификация делается через псевдотерминал
стандартной библиотекой (без sshpass и paramiko).
"""

from __future__ import annotations

import argparse
import errno
import os
import pty
import re
import select
import shlex
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vpnkit import (  # noqa: E402
    VpnKitError,
    fail,
    ok,
    parse_alias,
    parse_ssh_config,
    ssh_config_path,
    step,
    warn,
)

PASSWORD_PROMPT = re.compile(r"(password|пароль)[^\n]*:\s*$", re.IGNORECASE)
CONFIRM_PROMPT = re.compile(r"\(yes/no(/\[fingerprint\])?\)\?\s*$", re.IGNORECASE)
IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def key_paths(alias: str, ip: str) -> tuple[str, str]:
    private = os.path.expanduser(f"~/.ssh/id_ed25519_vps_{alias}_{ip}")
    return private, private + ".pub"


def ensure_key(alias: str, ip: str) -> tuple[str, str]:
    """Создаёт ключевую пару, если её ещё нет. Существующую не трогает."""
    private, public = key_paths(alias, ip)
    ssh_dir = os.path.dirname(private)
    os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
    os.chmod(ssh_dir, 0o700)

    if os.path.exists(private):
        if not os.path.exists(public):
            raise VpnKitError(
                f"приватный ключ {private} есть, а публичного {public} нет; "
                "восстановите его командой: "
                f"ssh-keygen -y -f {shlex.quote(private)} > {shlex.quote(public)}"
            )
        ok(f"ключ уже есть: {private}")
        return private, public

    step(f"создаю ключ {private}")
    subprocess.run(
        [
            "ssh-keygen",
            "-t", "ed25519",
            "-N", "",
            "-C", f"{alias}_{ip}",
            "-f", private,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    ok(f"ключ создан: {private}")
    return private, public


def run_with_password(argv: list[str], password: str, timeout: float = 120.0) -> tuple[int, str]:
    """Запускает команду в псевдотерминале и отвечает на запрос пароля.

    ssh читает пароль только с терминала, поэтому обычного stdin недостаточно —
    нужен именно pty.
    """
    pid, fd = pty.fork()
    if pid == 0:  # дочерний процесс
        os.execvp(argv[0], argv)
        os._exit(127)  # недостижимо

    transcript = bytearray()
    tail = bytearray()
    password_sent = False

    started = time.monotonic()
    try:
        while True:
            if time.monotonic() - started > timeout:
                os.kill(pid, 9)
                raise VpnKitError("сервер не ответил вовремя при входе по паролю")
            try:
                ready, _, _ = select.select([fd], [], [], 1.0)
            except InterruptedError:
                continue
            if fd in ready:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as exc:
                    if exc.errno == errno.EIO:  # ребёнок закрыл pty — это норма
                        break
                    raise
                if not chunk:
                    break
                transcript.extend(chunk)
                tail.extend(chunk)
                del tail[:-400]
                # Хвост может обрываться посреди UTF-8 — декодируем терпимо.
                recent = bytes(tail).decode("utf-8", "ignore")

                if not password_sent and PASSWORD_PROMPT.search(recent):
                    os.write(fd, password.encode() + b"\n")
                    password_sent = True
                    tail.clear()
                elif CONFIRM_PROMPT.search(recent):
                    os.write(fd, b"yes\n")
                    tail.clear()
            else:
                _, status = os.waitpid(pid, os.WNOHANG)
                if status:
                    break
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status
    text = transcript.decode("utf-8", "replace")
    if not password_sent and code != 0:
        warn("сервер ни разу не спросил пароль — возможно, парольный вход отключён")
    return code, text


def push_public_key(ip: str, user: str, password: str, public_key_path: str) -> None:
    """Кладёт публичный ключ в authorized_keys на сервере, зайдя по паролю."""
    with open(public_key_path, encoding="utf-8") as fh:
        pubkey = fh.read().strip()

    remote = (
        "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; "
        "chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys; "
        f"grep -qxF {shlex.quote(pubkey)} ~/.ssh/authorized_keys "
        f"|| printf '%s\\n' {shlex.quote(pubkey)} >> ~/.ssh/authorized_keys; "
        "echo VPNKIT_KEY_INSTALLED"
    )

    step(f"копирую публичный ключ на {user}@{ip}")
    code, output = run_with_password(
        [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=password,keyboard-interactive",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "ConnectTimeout=20",
            "-l", user,
            ip,
            remote,
        ],
        password,
    )

    if "VPNKIT_KEY_INSTALLED" not in output:
        # Некоторые серверы включают эхо на вводе — вычищаем пароль из вывода,
        # чтобы он не утёк в терминал и в логи.
        safe = output.replace(password, "***") if password else output
        tail = "\n".join(safe.strip().splitlines()[-8:])
        raise VpnKitError(
            f"не удалось положить ключ на сервер (код {code}). Вывод ssh:\n{tail}"
        )
    ok("публичный ключ на сервере")


def update_ssh_config(host_alias: str, ip: str, user: str, private_key: str) -> None:
    """Дописывает или обновляет блок Host в ``~/.ssh/config``."""
    path = ssh_config_path()
    key_ref = private_key.replace(os.path.expanduser("~"), "~", 1)
    block = (
        f"Host {host_alias}\n"
        f"    HostName {ip}\n"
        f"    User {user}\n"
        f"    IdentityFile {key_ref}\n"
        f"    IdentitiesOnly yes\n"
    )

    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(block)
        os.chmod(path, 0o600)
        ok(f"создал ~/.ssh/config и добавил {host_alias}")
        return

    with open(path, encoding="utf-8") as fh:
        content = fh.read()

    if host_alias in parse_ssh_config():
        # Вырезаем старый блок целиком: от строки Host до следующего Host.
        lines = content.splitlines(keepends=True)
        out: list[str] = []
        skipping = False
        for line in lines:
            if re.match(rf"^\s*Host\s+{re.escape(host_alias)}\s*$", line):
                skipping = True
                continue
            if skipping and re.match(r"^\s*Host\s+\S", line):
                skipping = False
            if not skipping:
                out.append(line)
        content = "".join(out).rstrip("\n") + "\n"
        warn(f"запись {host_alias} уже была — перезаписал")

    if content and not content.endswith("\n\n"):
        content = content.rstrip("\n") + "\n\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content + block)
    os.chmod(path, 0o600)
    ok(f"в ~/.ssh/config добавлен Host {host_alias}")


def verify(host_alias: str) -> bool:
    step(f"проверяю вход по ключу: ssh {host_alias}")
    proc = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=20",
            host_alias,
            "echo VPNKIT_OK",
        ],
        capture_output=True,
        text=True,
    )
    if "VPNKIT_OK" in proc.stdout:
        ok(f"готово, дальше ходите как: ssh {host_alias}")
        return True
    fail(f"вход по ключу не заработал: {proc.stderr.strip()}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Завести SSH-ключ под новый VPS и прописать его в ~/.ssh/config",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("alias", help="алиас хостинга и страны, например timeweb_nl")
    parser.add_argument("ip", help="IP-адрес сервера")
    parser.add_argument("password", help="пароль пользователя на сервере")
    parser.add_argument(
        "user", nargs="?", default="root", help="пользователь на сервере (по умолчанию root)"
    )
    args = parser.parse_args()

    try:
        parse_alias(args.alias)
        if not IPV4_RE.match(args.ip):
            raise VpnKitError(f"{args.ip!r} не похож на IPv4-адрес")

        host_alias = f"{args.alias}_{args.ip}"
        private, public = ensure_key(args.alias, args.ip)
        push_public_key(args.ip, args.user, args.password, public)
        update_ssh_config(host_alias, args.ip, args.user, private)
        return 0 if verify(host_alias) else 1
    except VpnKitError as exc:
        fail(str(exc))
        return 1
    except subprocess.CalledProcessError as exc:
        fail(f"{exc}\n{exc.stderr}")
        return 1
    except KeyboardInterrupt:
        fail("прервано")
        return 130


if __name__ == "__main__":
    sys.exit(main())
