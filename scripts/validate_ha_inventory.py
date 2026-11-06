#!/usr/bin/env python3
"""Offline Wazuh HA *architecture* inventory validator. Not a deployment or runtime HA test.

Never verifies failover, cross-zone networking, snapshot durability, DNS, quorum, or credentials.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

EXPECTED = '56ece955b1107b7b62823afae5b7057e1dab9d98'
TOKEN = re.compile(r'^[a-z0-9][a-z0-9.-]{2,100}$')


class ArchitectureError(Exception):
    pass


def validate(doc: dict) -> dict:
    if not isinstance(doc, dict) or doc.get('schema_version') != 1 or doc.get('wazuh_version') != '4.14.9' or doc.get('upstream_commit') != EXPECTED:
        raise ArchitectureError('Inventory schema or pinned upstream version mismatch')
    groups = {}
    for name, minimum in [('indexers', 3), ('managers', 2), ('dashboards', 2)]:
        rows = doc.get(name)
        if not isinstance(rows, list) or len(rows) < minimum or len(rows) > 12:
            raise ArchitectureError(f'{name}: insufficient or excessive independently deployable components')
        seen_name, seen_host, seen_domain = set(), set(), set()
        for entry in rows:
            if not isinstance(entry, dict) or not all(isinstance(entry.get(k), str) and TOKEN.fullmatch(entry[k]) for k in ('name', 'host', 'failure_domain')):
                raise ArchitectureError(f'{name}: missing or unsafe node identity')
            for seen, key in [(seen_name, 'name'), (seen_host, 'host'), (seen_domain, 'failure_domain')]:
                if entry[key] in seen:
                    raise ArchitectureError(f'{name}: duplicate {key} does not meet HA architecture contract')
                seen.add(entry[key])
        groups[name] = seen_name
    all_hosts = [x['host'] for name in ('indexers','managers','dashboards') for x in doc[name]]
    if len(all_hosts) != len(set(all_hosts)):
        raise ArchitectureError('HA inventory must use distinct component hosts')
    for ingress, targets in (('agent_ingress', groups['managers']), ('dashboard_ingress', groups['dashboards'])):
        row = doc.get(ingress)
        if not isinstance(row, dict) or set(row.get('backends', [])) != targets or not isinstance(row.get('name'), str) or not TOKEN.fullmatch(row['name']):
            raise ArchitectureError(ingress + ': backends must include all named nodes')
        if row.get('health_probe') not in ('tcp:1514', 'https:5601'):
            raise ArchitectureError(ingress + ': health-check protocol not approved')
    if doc['agent_ingress']['health_probe'] != 'tcp:1514' or doc['dashboard_ingress']['health_probe'] != 'https:5601':
        raise ArchitectureError('Incorrect ingress health-check mapping')
    return {'topology': 'architecture_check_passed',
            'indexers': len(groups['indexers']), 'managers': len(groups['managers']),
            'dashboards': len(groups['dashboards']),
            'runtime_evidence': 'NOT_CHECKED', 'enterprise_approval': 'NOT_GRANTED'}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory', type=Path, default=Path('deployments/ha/inventory.example.json'))
    args = p.parse_args(argv)
    try:
        if args.inventory.is_symlink() or args.inventory.stat().st_size > 65536:
            raise ArchitectureError('Inventory must be a bounded regular JSON file')
        doc = json.loads(args.inventory.read_text(encoding='utf-8'))
        print(json.dumps(validate(doc), sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, ArchitectureError):
        print('HA inventory invalid or unreadable; no HA readiness claim allowed', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
