#!/usr/bin/env python3
"""Provision Wazuh v4.14.9 with unique credentials and matching indexer hashes.

This is a *new deployment* initializer, not a credential rotation tool.
Existing Wazuh volumes need the vendor password-rotation procedure instead.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
GENERATED = ROOT / "config" / "generated"
ENV = ROOT / ".env"
EXAMPLE = ROOT / ".env.example"
MANAGER_TEMPLATE = ROOT / "config" / "wazuh_cluster" / "wazuh_manager.conf"
EXPECTED = ("INDEXER_PASSWORD", "DASHBOARD_PASSWORD", "API_PASSWORD")
DEFAULTS = ("DASHBOARD_BIND_ADDRESS", "AGENT_BIND_ADDRESS", "API_BIND_ADDRESS")
PLACEHOLDER = "{{CLUSTER_KEY}}"


def random_secret() -> str:
    """Create a 48-character secret obeying Wazuh password character rules."""
    from string import ascii_lowercase, ascii_uppercase, digits

    punctuation = "._-+@%="
    allowed = ascii_lowercase + ascii_uppercase + digits + punctuation
    # The vendor password rules require each category, not just entropy.
    chars = [secrets.choice(group) for group in (ascii_lowercase, ascii_uppercase, digits, punctuation)]
    chars.extend(secrets.choice(allowed) for _ in range(44))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_password_hash(password: str) -> str:
    try:
        import bcrypt
    except ImportError as exc:
        raise RuntimeError("Install requirements-bootstrap.txt first") from exc
    if len(password.encode("utf-8")) > 72:
        raise ValueError("bcrypt passwords must be 72 bytes or fewer")
    raw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")
    # Wazuh indexer 4.x uses the $2a$ bcrypt identifier in its stock users file.
    # For our generated ASCII-only passwords, $2a$ and $2b$ verify identically.
    return "$2a$" + raw[4:] if raw.startswith("$2b$") else raw


def make_internal_users(indexer: str, dashboard: str) -> str:
    admin_hash = generate_password_hash(indexer)
    dashboard_hash = generate_password_hash(dashboard)
    return (
        "# Initial indexer security users; generated locally. Never commit.\n"
        "_meta:\n  type: internalusers\n  config_version: 2\n"
        "admin:\n"
        f"  hash: {json.dumps(admin_hash)}\n"
        "  reserved: true\n  backend_roles: [admin]\n"
        "  description: 'Indexer administrator'\n"
        "kibanaserver:\n"
        f"  hash: {json.dumps(dashboard_hash)}\n"
        "  reserved: true\n  description: 'Dashboard service'\n"
    )


def make_dashboard_config(password: str) -> str:
    return (
        "# Wazuh dashboard API connection, provisioned locally. Never commit.\n"
        "hosts:\n  - 1513629884013:\n"
        '      url: "https://wazuh.manager"\n'
        "      port: 55000\n"
        '      username: "wazuh-wui"\n'
        f"      password: {json.dumps(password)}\n"
        "      run_as: true\n"
    )


def make_manager_config(cluster_key: str) -> str:
    template = MANAGER_TEMPLATE.read_text(encoding="utf-8")
    if template.count(PLACEHOLDER) != 1:
        raise RuntimeError("Expected exactly one cluster key placeholder in manager config")
    return template.replace(PLACEHOLDER, cluster_key)


def validate_defaults(contents: str) -> None:
    keys = []
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z_]+", key) or not value:
            raise ValueError("Invalid .env.example entry")
        keys.append(key)
    if set(keys) != set(DEFAULTS) or len(keys) != len(DEFAULTS):
        raise ValueError("Unexpected keys in .env.example")


def write_secure(path: Path, contents: str, mode: int) -> None:
    # Exclusive creation: never overwrite a secret or an existing deployment.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
            output.write(contents)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def check_initialized() -> list[str]:
    paths = (ENV, GENERATED / "internal_users.yml", GENERATED / "wazuh.yml", GENERATED / "wazuh_manager.conf", GENERATED / "authd.pass")
    missing = [str(path.relative_to(ROOT)) for path in paths if not path.is_file()]
    if missing:
        return missing
    content = ENV.read_text(encoding="utf-8")
    keys = {line.partition("=")[0] for line in content.splitlines() if "=" in line}
    if not set(EXPECTED).issubset(keys):
        return [".env is missing required credentials"]
    return []


def bootstrap() -> None:
    expected_paths = (ENV, GENERATED / "internal_users.yml", GENERATED / "wazuh.yml", GENERATED / "wazuh_manager.conf", GENERATED / "authd.pass")
    if any(path.exists() for path in expected_paths):
        if not check_initialized():
            print("Already initialized. Existing credentials were preserved.")
            return
        raise RuntimeError("Partial initialization detected; inspect files before retrying. No credentials changed.")

    defaults = EXAMPLE.read_text(encoding="utf-8")
    validate_defaults(defaults)
    credentials = {name: random_secret() for name in EXPECTED}
    manager = make_manager_config(secrets.token_hex(16))
    enrollment_password = secrets.token_hex(32)
    users = make_internal_users(credentials["INDEXER_PASSWORD"], credentials["DASHBOARD_PASSWORD"])
    dashboard = make_dashboard_config(credentials["API_PASSWORD"])
    env_body = defaults.rstrip("\n") + "\n" + "".join(f"{key}={value}\n" for key, value in credentials.items())

    GENERATED.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(GENERATED, 0o700)
    # Docker processes need to read bind-mounted files; the parent host folder
    # is 0700. Do not change the host folder's permissions.
    files = (
        (GENERATED / "internal_users.yml", users, 0o644),
        (GENERATED / "wazuh.yml", dashboard, 0o644),
        (GENERATED / "wazuh_manager.conf", manager, 0o644),
        (GENERATED / "authd.pass", enrollment_password + "\n", 0o640),
        (ENV, env_body, 0o600),
    )
    for path, content, mode in files:
        write_secure(path, content, mode)
    print("Credentials, enrollment password and configuration created. Keep .env and config/generated private.")
    print("Next: docker compose -f generate-indexer-certs.yml run --rm generator")
    print("Then: docker compose config --quiet && docker compose up -d")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check whether initialization is complete")
    options = parser.parse_args()
    try:
        if options.check:
            missing = check_initialized()
            if missing:
                print("Not initialized: " + ", ".join(missing), file=sys.stderr)
                return 1
            print("Credential files are present (service/runtime validation not performed).")
            return 0
        bootstrap()
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Initialization error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
