#!/usr/bin/env python3
"""Advisory upstream Wazuh stable release monitor; never changes deployment files."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
import urllib.request

URL = "https://api.github.com/repos/wazuh/wazuh-docker/releases/latest"
ROOT = Path(__file__).resolve().parents[1]


def current_version(content: str) -> str:
    tags = re.findall(r"image:\s*wazuh/wazuh-(?:manager|dashboard|indexer):([0-9]+\.[0-9]+\.[0-9]+)", content)
    if len(tags) != 3 or len(set(tags)) != 1:
        raise ValueError("Wazuh component tags are missing or out of sync")
    return tags[0]


def latest_version(response: dict) -> str:
    tag = response.get("tag_name") if isinstance(response, dict) else None
    if not isinstance(tag, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag) or response.get("prerelease") is True:
        raise ValueError("Unexpected upstream stable release response")
    return tag[1:]


def fetch_latest() -> str:
    req = urllib.request.Request(URL, headers={"Accept": "application/vnd.github+json", "User-Agent": "redoracle-wazuh-release-monitor"})
    with urllib.request.urlopen(req, timeout=12) as response:
        raw = response.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError("Oversized upstream release response")
    return latest_version(json.loads(raw))


def main() -> int:
    try:
        current = current_version((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
        latest = fetch_latest()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("Unable to verify upstream stable release; no upgrade performed", file=sys.stderr)
        return 2
    except Exception:  # urllib/network errors must not leak environment details.
        print("Release source unavailable; no upgrade performed", file=sys.stderr)
        return 2
    print(f"Deployed release bundle: {current}; official latest stable: {latest}")
    if tuple(map(int, latest.split('.'))) > tuple(map(int, current.split('.'))):
        print("Newer official stable release available; schedule a coordinated upgrade review")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
