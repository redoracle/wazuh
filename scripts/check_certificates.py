#!/usr/bin/env python3
"""Non-destructive Wazuh certificate and private-key security checks.

OpenSSL runs without printing certificate details or key material. Missing files,
expired/near-expiry certificates and unexpected permissions fail closed. This is
an operator gate, not a replacement for live TLS connection tests.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
CERT_DIR = ROOT / 'config/wazuh_indexer_ssl_certs'
SERVICES = ('wazuh.indexer', 'wazuh.manager', 'wazuh.dashboard')
CERTS = ('root-ca.pem', 'root-ca-manager.pem', 'admin.pem') + tuple(f'{x}.pem' for x in SERVICES)
KEYS = ('admin-key.pem',) + tuple(f'{x}-key.pem' for x in SERVICES)


def secure_file(path: Path, *, private: bool) -> bool:
    """Never follow a symlink; disallow any world access for private keys."""
    try:
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode):
        return False
    if private and stat.S_IMODE(metadata.st_mode) & 0o007:
        return False
    return True


def openssl_ok(*args: str) -> bool:
    try:
        return subprocess.run(['openssl', *args], capture_output=True, timeout=15, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def matching_key_pair(certificate: Path, key: Path) -> bool:
    """Compare public keys without printing or exporting private key contents."""
    try:
        cert = subprocess.run(
            ['openssl', 'x509', '-pubkey', '-noout', '-in', str(certificate)],
            capture_output=True, timeout=15, check=False)
        private = subprocess.run(
            ['openssl', 'pkey', '-pubout', '-in', str(key)],
            capture_output=True, timeout=15, check=False)
        return cert.returncode == 0 and private.returncode == 0 and bool(cert.stdout) and cert.stdout == private.stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def inspect(directory: Path = CERT_DIR, *, min_days: int = 30) -> dict[str, bool]:
    if not 0 <= min_days <= 3650:
        raise ValueError('min_days must be 0..3650')
    checks: dict[str, bool] = {}
    checks['openssl_available'] = shutil.which('openssl') is not None
    # Directories containing private keys must not be searchable by other users.
    try:
        metadata = directory.lstat()
        checks['certificate_directory_private'] = stat.S_ISDIR(metadata.st_mode) and not (stat.S_IMODE(metadata.st_mode) & 0o007)
    except OSError:
        checks['certificate_directory_private'] = False
    for name in CERTS:
        path = directory / name
        checks[f'certificate_present:{name}'] = secure_file(path, private=False)
        if checks[f'certificate_present:{name}'] and checks['openssl_available']:
            checks[f'certificate_valid_for_{min_days}d:{name}'] = openssl_ok(
                'x509', '-in', str(path), '-noout', '-checkend', str(min_days * 86400))
    for name in KEYS:
        checks[f'private_key_permissions:{name}'] = secure_file(directory / name, private=True)
    if checks['openssl_available']:
        for certificate, key in (('admin.pem', 'admin-key.pem'), *(
            (f'{service}.pem', f'{service}-key.pem') for service in SERVICES)):
            if secure_file(directory / certificate, private=False) and secure_file(directory / key, private=True):
                checks[f'keypair_matches:{certificate}'] = matching_key_pair(directory / certificate, directory / key)
    root = directory / 'root-ca.pem'
    if secure_file(root, private=False) and checks['openssl_available']:
        # Check trust AND the server identity, never bypass verification.
        for service in SERVICES:
            cert = directory / f'{service}.pem'
            if secure_file(cert, private=False):
                checks[f'chain_and_hostname:{service}'] = openssl_ok(
                    'verify', '-CAfile', str(root), '-verify_hostname', service, str(cert))
        admin = directory / 'admin.pem'
        if secure_file(admin, private=False):
            checks['admin_cert_chain'] = openssl_ok('verify', '-CAfile', str(root), str(admin))
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cert-dir', type=Path, default=CERT_DIR)
    parser.add_argument('--min-days', type=int, default=30)
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        checks = inspect(args.cert_dir, min_days=args.min_days)
    except ValueError as exc:
        parser.error(str(exc))
    passed = all(checks.values())
    if args.json:
        print(json.dumps({'passed': passed, 'checks': checks}, sort_keys=True))
    else:
        for key, okay in checks.items():
            print(f'{"PASS" if okay else "FAIL"}: {key}')
        print('Certificate checks ' + ('passed' if passed else 'failed'))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
