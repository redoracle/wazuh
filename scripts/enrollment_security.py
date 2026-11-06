#!/usr/bin/env python3
"""Explicit, local-only conversion of an initialized Wazuh 4.x manager to password enrollment.

Does not restart containers, expose credentials, overwrite existing passwords or enroll agents.
The generated enrollment secret must be distributed to agents through a protected channel.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TAG_NO = '<use_password>no</use_password>'
TAG_YES = '<use_password>yes</use_password>'


def secure_directory(path: Path) -> None:
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or stat.S_IMODE(meta.st_mode) & 0o077:
        raise ValueError('Generated configuration directory must be private (0700) and not a symlink')


def secure_file(path: Path, *, secret: bool = False) -> None:
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or (secret and stat.S_IMODE(meta.st_mode) & 0o007):
        raise ValueError('Enrollment configuration must be a regular file without world-readable bits')


def new_password() -> str:
    # A Wazuh agent password is a shared bearer credential, not an Indexer password.
    return secrets.token_hex(32)


def save_exclusive(path: Path, data: str, mode: int) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            out.write(data)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def prepare(root: Path, *, apply: bool = False) -> str:
    config_dir = root / 'config' / 'generated'
    secure_directory(config_dir)
    manager = config_dir / 'wazuh_manager.conf'
    password = config_dir / 'authd.pass'
    secure_file(manager)
    content = manager.read_text(encoding='utf-8')
    if content.count(TAG_NO) + content.count(TAG_YES) != 1:
        raise ValueError('Expected exactly one supported Wazuh authd password element')
    if password.exists() or password.is_symlink():
        secure_file(password, secret=True)
        if not password.read_text(encoding='utf-8').strip() or password.stat().st_size > 256:
            raise ValueError('Existing enrollment password file is invalid')
    if content.count(TAG_YES) == 1 and password.is_file():
        return 'already enabled (no changes)'
    if not apply:
        return 'changes required; rerun with --apply during an approved maintenance window'
    if TAG_NO in content and (config_dir / 'wazuh_manager.conf.pre-enrollment').exists():
        raise ValueError('Unexpected existing pre-enrollment backup; inspect manually before continuing')
    if not password.exists():
        save_exclusive(password, new_password() + '\n', 0o640)
    if TAG_NO in content:
        # Use a unique, private backup that cannot be overwritten. Never print its contents.
        backup = config_dir / 'wazuh_manager.conf.pre-enrollment'
        save_exclusive(backup, content, 0o640)
        fd, temp = tempfile.mkstemp(prefix='.manager-auth-', dir=config_dir)
        try:
            os.fchmod(fd, stat.S_IMODE(manager.stat().st_mode))
            with os.fdopen(fd, 'w', encoding='utf-8') as out:
                out.write(content.replace(TAG_NO, TAG_YES))
            os.replace(temp, manager)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    return 'enrollment configured on disk; controlled manager recreation and negative enrollment test required'


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--apply', action='store_true', help='explicitly modify generated local files; never restart containers')
    args = p.parse_args(argv)
    try:
        print(prepare(ROOT, apply=args.apply))
    except (OSError, ValueError, UnicodeError):
        print('Enrollment conversion failed; inspect protected generated files locally', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
