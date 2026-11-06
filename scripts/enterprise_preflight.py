#!/usr/bin/env python3
"""Read-only deployment policy checks; not a substitute for runtime acceptance tests.

Checks metadata and optional host files. Never emits credential values.
The enterprise profile is intentionally fail-closed for unverified operational gates.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import stat
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
WAZUH_VERSION = "4.14.9"
CENTRAL = ("wazuh.manager", "wazuh.indexer", "wazuh.dashboard")
SECRET_KEYS = ("INDEXER_PASSWORD", "DASHBOARD_PASSWORD", "API_PASSWORD")
BIND_KEYS = ("DASHBOARD_BIND_ADDRESS", "AGENT_BIND_ADDRESS", "API_BIND_ADDRESS")


class StrictLoader(yaml.SafeLoader):
    """Reject duplicate YAML keys rather than silently overriding policy settings."""


def strict_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in result:
            raise ValueError("Duplicate YAML mapping key")
        result[key] = loader.construct_object(value_node)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, strict_mapping)


def read_yaml(path: Path) -> dict:
    result = yaml.load(path.read_text(encoding="utf-8"), Loader=StrictLoader)
    if not isinstance(result, dict):
        raise ValueError("Expected YAML mapping")
    return result


@dataclass(frozen=True)
class Finding:
    control: str
    result: str
    reason: str
    action: str


def evaluate(root: Path = ROOT, *, profile: str = "controlled", host: bool = False) -> list[Finding]:
    if profile not in ("controlled", "enterprise"):
        raise ValueError("Invalid policy profile")
    out: list[Finding] = []

    def record(control: str, acceptable: bool, reason: str, action: str, *, enterprise_only: bool = False) -> None:
        status = "pass" if acceptable else ("block" if profile == "enterprise" or not enterprise_only else "warn")
        out.append(Finding(control, status, reason, action))

    compose = read_yaml(root / "docker-compose.yml")
    overlay = read_yaml(root / "docker-compose.ai.yml")
    indexer = read_yaml(root / "config/wazuh_indexer/wazuh.indexer.yml")
    services = compose.get("services", {}) if isinstance(compose, dict) else {}
    record("release_bundle", set(services) == set(CENTRAL) and all(
        services.get(name, {}).get("image") == f"wazuh/wazuh-{name.split('.')[-1]}:{WAZUH_VERSION}"
        for name in CENTRAL), "Three Wazuh components must use one verified stable release",
        "Review the complete upstream release bundle and upgrade documentation")

    indexer_service = services.get("wazuh.indexer", {})
    record("indexer_exposure", not indexer_service.get("ports") and not indexer_service.get("network_mode"),
           "The Indexer API must not be published on the host", "Remove exposed Indexer ports and host-network mode")

    port_entries = [(name, entry) for name in ("wazuh.manager", "wazuh.dashboard")
                    for entry in services.get(name, {}).get("ports", [])]
    def loopback_default(entry: object) -> bool:
        return (isinstance(entry, str) and bool(re.fullmatch(
            r"\$\{(?:AGENT|DASHBOARD|API)_BIND_ADDRESS:-127\.0\.0\.1\}:\d+:\d+/tcp", entry)))
    record("safe_port_defaults", len(port_entries) == 4 and all(loopback_default(p) for _, p in port_entries),
           "Published ports must default to 127.0.0.1", "Use loopback defaults and controlled ingress")

    all_services = {**services, **overlay.get("services", {})}
    dangerous = any(
        svc.get("privileged") or svc.get("network_mode") == "host" or
        svc.get("pid") == "host" or svc.get("cap_add") or
        any("docker.sock" in str(v) for v in svc.get("volumes", []))
        for svc in all_services.values()
    )
    record("host_isolation", not dangerous, "No service may use host PID/network, Docker socket or elevated privileges",
           "Remove host privileges and privileged mounts")

    ai = overlay.get("services", {})
    worker, model = ai.get("ai-triage", {}), ai.get("ai-ollama", {})
    record("ai_opt_in", set(ai) == {"ai-triage", "ai-ollama"} and
           all(x.get("profiles") == ["ai"] and not x.get("ports") for x in (worker, model)) and
           worker.get("read_only") is True and worker.get("cap_drop") == ["ALL"] and
           model.get("networks") == ["ai-model-net"],
           "AI must be opt-in, not host-published, and have no model access to the Wazuh bridge",
           "Restore the read-only worker, opt-in profile, and isolated model network")

    for name, service in all_services.items():
        logging = service.get("logging", {})
        opts = logging.get("options", {}) if isinstance(logging, dict) else {}
        record(f"bounded_logs_{name}", logging.get("driver") == "json-file" and
               opts.get("max-size") == "10m" and opts.get("max-file") == "5",
               "Each service should rotate its Docker stdout/stderr logs", "Configure JSON log rotation for this service")

    # Upstream 4.14.x sample explicitly disables disk thresholds. Detect, do not silently
    # change a setting whose implications depend on disk layout and indexer version.
    record("disk_watermarks", indexer.get("cluster.routing.allocation.disk.threshold_enabled") is not False,
           "Indexer disk allocation thresholds are disabled in the current release-based config",
           "Validate vendor-compatible watermark policy, capacity alerts and full-disk recovery in staging",
           enterprise_only=True)
    record("immutable_images", all("@sha256:" in str(svc.get("image", "")) for svc in all_services.values()),
           "Component image version tags are not immutable digests", "Record and pin approved multi-architecture image digests",
           enterprise_only=True)

    manager = (root / "config/wazuh_cluster/wazuh_manager.conf").read_text(encoding="utf-8")
    record("enrollment_auth", "<use_password>yes</use_password>" in manager,
           "The upstream manager template does not require an enrollment password",
           "Validate vendor-supported authenticated enrollment before any exposure beyond loopback",
           enterprise_only=True)

    if host:
        env_file = root / ".env"
        is_safe_env = env_file.is_file() and not env_file.is_symlink() and (
            os.name != "posix" or stat.S_IMODE(env_file.stat().st_mode) & 0o077 == 0)
        record("secret_file_permissions", is_safe_env, "Host .env must exist and be owner-only readable",
               "Bootstrap in a private directory; set .env to 0600 and never use symlinks")
        cert_dir = root / "config/wazuh_indexer_ssl_certs"
        certs = ("root-ca.pem", "wazuh.indexer.pem", "wazuh.manager.pem", "wazuh.dashboard.pem")
        record("certificate_presence", all((cert_dir / name).is_file() and
               not (cert_dir / name).is_symlink() for name in certs),
               "Expected certificates must exist and must not be symlinks",
               "Generate and verify certificate trust, SAN, expiry and private-key permissions")
        generated = root / "config/generated"
        try:
            config_mode = generated.lstat()
            config_safe = stat.S_ISDIR(config_mode.st_mode) and stat.S_IMODE(config_mode.st_mode) & 0o007 == 0
        except OSError:
            config_safe = False
        record("generated_config_directory", config_safe,
               "Generated Indexer hashes, Manager key and dashboard API credentials need private directory access",
               "Keep config/generated/ a non-symlink, non-world-searchable directory and verify container access")
        keys = ("admin-key.pem", "wazuh.indexer-key.pem", "wazuh.manager-key.pem", "wazuh.dashboard-key.pem")
        keys_safe = True
        for key in keys:
            try:
                metadata = (cert_dir / key).lstat()
                keys_safe = keys_safe and stat.S_ISREG(metadata.st_mode) and stat.S_IMODE(metadata.st_mode) & 0o007 == 0
            except OSError:
                keys_safe = False
        record("certificate_private_key_access", keys_safe,
               "Private TLS keys must exist, must not be symlinks and must not be world-readable",
               "Run python3 scripts/check_certificates.py and stage-test UID/GID-compatible permissions",
               enterprise_only=True)
        if is_safe_env:
            # Parse only the three configured bind variables; never store or print secrets.
            binds = {}
            for line in env_file.read_text(encoding="utf-8").splitlines():
                key, separator, value = line.partition("=")
                if separator and key.strip() in BIND_KEYS:
                    binds[key.strip()] = value.strip()
            unrestricted = any(binds.get(k, "127.0.0.1") not in ("127.0.0.1", "::1") for k in BIND_KEYS)
            record("runtime_host_exposure", not unrestricted,
                   "A configured host interface exposes Wazuh beyond loopback",
                   "Approve an ingress design, firewall/VPN, enrollment authentication and trusted server certificates",
                   enterprise_only=True)

    # These are operational controls that a source repository cannot certify.
    if profile == "enterprise":
        out.extend([
            Finding("high_availability", "block", "The Docker topology contains one Indexer and one Manager",
                    "Adopt and stage-test the official multi-node Wazuh deployment"),
            Finding("snapshot_restore", "block", "No tested off-host snapshot and full restore evidence was supplied",
                    "Test consistent Indexer snapshots and manager/config/credential recovery"),
            Finding("network_policy", "block", "Compose bridge networks do not enforce enterprise egress policy",
                    "Enforce and measure host/network egress segmentation and agent ingress control"),
            Finding("live_acceptance", "block", "CI does not start Wazuh, enroll agents or test failover/restore",
                    "Execute the production acceptance runbook with recorded sign-offs"),
            Finding("governance", "block", "Branch protection and organizational controls require GitHub administrator verification",
                    "Require protected branches, independent reviews, secret scanning and supply-chain reviews"),
        ])
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("controlled", "enterprise"), default="controlled")
    parser.add_argument("--host", action="store_true", help="Inspect local paths and host bind variables without printing values")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable, credential-free report")
    args = parser.parse_args(argv)
    try:
        checks = evaluate(profile=args.profile, host=args.host)
    except (OSError, ValueError, yaml.YAMLError):
        print("Preflight cannot parse the repository configuration; inspect local files", file=sys.stderr)
        return 2
    rejected = [check for check in checks if check.result == "block"]
    report = {"profile": args.profile, "result": "block" if rejected else "pass",
              "host_checked": args.host, "checks": [asdict(item) for item in checks]}
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for item in checks:
            print(f"{item.result.upper():5}  {item.control}: {item.reason}")
        print(f"Result: {report['result']} (policy checks only; no runtime tests)")
    return 1 if rejected else 0


if __name__ == "__main__":
    raise SystemExit(main())
