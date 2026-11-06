#!/usr/bin/env python3
"""Non-invasive Docker Compose liveness/host-port inventory. Not an ingestion or recovery test.

Prints only bounded component status and never docker inspect/env, credentials or raw logs.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys

EXPECTED = {'wazuh.manager', 'wazuh.indexer', 'wazuh.dashboard'}


def parse_rows(output: str) -> list[dict]:
    output = output.strip()
    if len(output) > 100000 or not output:
        raise ValueError('Unexpected Docker Compose response size')
    try:
        if output.startswith('['):
            records = json.loads(output)
        else:
            records = [json.loads(row) for row in output.splitlines() if row.strip()]
    except ValueError as e:
        raise ValueError('Invalid Compose JSON response') from e
    if not isinstance(records, list) or not all(isinstance(x, dict) for x in records):
        raise ValueError('Invalid Compose row schema')
    return records


def probe(records: list[dict]) -> dict:
    statuses = {}
    for row in records:
        service = row.get('Service')
        if service not in EXPECTED:
            continue
        if service in statuses:
            raise ValueError('Duplicate Compose service instance found')
        status = str(row.get('State', '')).lower()
        health = str(row.get('Health', '')).lower()
        # Compose may not define a HEALTHCHECK; running is necessary, not sufficient.
        ok = status == 'running' and health not in ('unhealthy', 'starting')
        statuses[service] = {'running': ok, 'healthcheck_present': bool(health)}
    return {'component_status': {k: statuses.get(k, {'running': False, 'healthcheck_present': False})
                                 for k in sorted(EXPECTED)},
            'running_contract': all(statuses.get(k, {}).get('running') for k in EXPECTED),
            'ingestion_tested': False, 'failover_tested': False, 'backup_restored': False,
            'enterprise_approved': False}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compose-file', default='docker-compose.yml')
    args = p.parse_args(argv)
    if args.compose_file != 'docker-compose.yml':
        p.error('Only the reviewed default deployment is supported')
    try:
        process = subprocess.run(['docker', 'compose', '-f', args.compose_file,
                                  'ps', '--format', 'json'],
                                 check=True, text=True, capture_output=True, timeout=20)
        report = probe(parse_rows(process.stdout))
        print(json.dumps(report, sort_keys=True))
        return 0 if report['running_contract'] else 3
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        print('Docker runtime check failed; inspect local Compose health privately', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
