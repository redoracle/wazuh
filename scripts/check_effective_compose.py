#!/usr/bin/env python3
"""Validate the *resolved* Docker Compose model, without displaying secrets.

Call with `docker compose ... config --format json | python scripts/check_effective_compose.py`.
The JSON may contain service credentials and must never be stored or printed.
This is an offline config gate, not a firewall or runtime isolation test.
"""
from __future__ import annotations

import argparse
import json
import sys


class ComposePolicyError(ValueError):
    """Safe diagnostic containing only a named policy failure."""


BASE = {'wazuh.manager', 'wazuh.indexer', 'wazuh.dashboard'}
EXPECTED_PORTS = {
    'wazuh.manager': {(1514, '1514'), (1515, '1515'), (55000, '55000')},
    'wazuh.dashboard': {(5601, '443')},
}


def fail(message: str) -> None:
    raise ComposePolicyError(message)


def network_names(service: dict) -> set[str]:
    value = service.get('networks') or []
    if isinstance(value, dict):
        return set(value)
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return set(value)
    fail('Invalid effective network declaration')


def check(model: dict, *, ai: bool = False) -> dict:
    if not isinstance(model, dict) or not isinstance(model.get('services'), dict):
        fail('Resolved Compose model must contain services')
    services = model['services']
    expected = BASE | ({'ai-triage', 'ai-ollama'} if ai else set())
    if set(services) != expected:
        fail('Unexpected service set in resolved Compose model')

    for name, svc in services.items():
        if not isinstance(svc, dict):
            fail('Invalid service configuration')
        if (svc.get('privileged') is True or svc.get('network_mode') == 'host' or
                svc.get('pid') == 'host' or svc.get('cap_add')):
            fail('Host privileges not permitted: ' + name)
        if any('docker.sock' in str(mount) for mount in svc.get('volumes', [])):
            fail('Docker socket mount not permitted: ' + name)
        if name not in EXPECTED_PORTS and svc.get('ports'):
            fail('Unexpected host-published ports: ' + name)

    for name, expected_ports in EXPECTED_PORTS.items():
        actual = set()
        entries = services[name].get('ports') or []
        for port in entries:
            if not isinstance(port, dict):
                fail('Unrecognized effective port format: ' + name)
            if (port.get('host_ip') != '127.0.0.1' or
                    port.get('protocol', 'tcp') != 'tcp'):
                fail('Published service must bind loopback TCP: ' + name)
            try:
                key = (int(port['target']), str(port['published']))
            except (KeyError, TypeError, ValueError):
                fail('Invalid published port: ' + name)
            actual.add(key)
        if actual != expected_ports or len(entries) != len(expected_ports):
            fail('Published port inventory drift: ' + name)

    if ai:
        worker, model_service = services['ai-triage'], services['ai-ollama']
        if (worker.get('profiles') != ['ai'] or worker.get('read_only') is not True or
                'ALL' not in worker.get('cap_drop', []) or
                network_names(worker) != {'default', 'ai-model-net'}):
            fail('AI worker isolation policy not satisfied')
        if (model_service.get('profiles') != ['ai'] or
                network_names(model_service) != {'ai-model-net'}):
            fail('Local model must have AI-only network access')

    return {'result': 'pass', 'services_checked': len(services),
            'ai_profile_checked': ai, 'runtime_verified': False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ai', action='store_true', help='Require the isolated opt-in AI overlay')
    args = parser.parse_args(argv)
    try:
        # Deliberately never include the original Compose model or credentials
        # in errors or output; parsing stdin avoids files with exposed secrets.
        source = sys.stdin.read(1024 * 1024 + 1)
        if len(source) > 1024 * 1024:
            fail('Resolved Compose JSON exceeds allowed limit')
        result = check(json.loads(source), ai=args.ai)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ComposePolicyError, ValueError, TypeError) as exc:
        # json errors have no secret payloads because only fixed text is printed.
        print('Effective Compose policy check failed; review exposure and isolation', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
