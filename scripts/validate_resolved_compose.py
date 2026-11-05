"""Fail-closed validation of the *resolved* legacy Docker Compose model.

Use with ``docker compose config --format json | python -m scripts.validate_resolved_compose``.
The script never executes containers or reads/prints environment credentials.
It compares a machine-readable configuration against this repository's explicit
historical baseline and refuses silent runtime/privilege changes.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import PurePosixPath

WAZUH_TAG = '3.10.2_7.3.2'
BEATS_TAG = '7.4.2'
IMAGES = {
    'wazuh': f'wazuh/wazuh:{WAZUH_TAG}',
    'elasticsearch': f'wazuh/wazuh-elasticsearch:{WAZUH_TAG}',
    'kibana': f'wazuh/wazuh-kibana:{WAZUH_TAG}',
    'nginx': f'wazuh/wazuh-nginx:{WAZUH_TAG}',
    **{
        name: f'docker.elastic.co/beats/{name}:{BEATS_TAG}'
        for name in (
            'packetbeat', 'filebeat', 'auditbeat', 'journalbeat',
            'heartbeat', 'metricbeat',
        )
    },
}
IP_ADDRESSES = {
    'nginx': '172.13.0.101',
    'kibana': '172.13.0.102',
    'elasticsearch': '172.13.0.103',
    'wazuh': '172.13.0.104',
    'packetbeat': '172.13.0.105',
    'filebeat': '172.13.0.106',
    'auditbeat': '172.13.0.107',
    'journalbeat': '172.13.0.108',
    'heartbeat': '172.13.0.109',
    'metricbeat': '172.13.0.110',
}
# source, target, read-only. A socket mounted ro can STILL change host state.
MOUNTS = {
    'wazuh': [],
    'elasticsearch': [('/DATA/Wazuh/Elasticsearch', '/Datak', False)],
    'kibana': [('/DATA/Wazuh/Kibana', '/Datak', False)],
    'nginx': [('/DATA/Wazuh/Nginx', '/Datak', False)],
    'packetbeat': [],
    'filebeat': [
        ('/var/lib/docker/containers', '/var/lib/docker/containers', True),
        ('/var/run/docker.sock', '/var/run/docker.sock', True),
        ('/DATA/Wazuh/Filebeat/filebeat.yml', '/etc/filebeat/filebeat.yml', True),
        ('/DATA/Wazuh/Filebeat', '/Datak', False),
    ],
    'auditbeat': [
        ('/DATA/Wazuh/Auditbeat/auditbeat.yml', '/etc/auditbeat/auditbeat.yml', True),
        ('/DATA/Wazuh/Auditbeat', '/Datak', False),
    ],
    'journalbeat': [
        ('/DATA/Wazuh/Journalbeat', '/Datak', False),
        ('/run/log/journal', '/var/log/journal', True),
        ('/etc/machine-id', '/etc/machine-id', True),
        ('/run/systemd', '/run/systemd', True),
        ('/etc/hostname', '/etc/hostname', True),
    ],
    'heartbeat': [('/DATA/Wazuh/Heartbeat', '/Datak', False)],
    'metricbeat': [
        ('/DATA/Wazuh/Metricbeat/metricbeat.yml', '/etc/metricbeat/metricbeat.yml', True),
        ('/DATA/Wazuh/Metricbeat', '/Datak', False),
        ('/', '/hostfs', True),
        ('/proc', '/hostfs/proc', True),
        ('/sys/fs/cgroup', '/hostfs/sys/fs/cgroup', True),
        ('/var/run/docker.sock', '/var/run/docker.sock', True),
    ],
}
CAPABILITIES = {
    'packetbeat': {'net_raw', 'net_admin'},
    'auditbeat': {'audit_control', 'audit_read'},
    'metricbeat': {'dac_read_search', 'sys_ptrace'},
}


# Only fields observed in the historical Compose file may appear. New commands,
# entrypoints, privilege controls or environment keys require explicit review.
APPROVED_SERVICE_FIELDS = {
    'image', 'hostname', 'restart', 'expose', 'networks', 'volumes',
    'environment', 'ulimits', 'mem_limit', 'depends_on', 'cap_add', 'pid',
    'user',
}
ENVIRONMENT_KEYS = {
    'elasticsearch': {'ES_JAVA_OPTS', 'ELASTIC_CLUSTER',
                      'CLUSTER_NODE_MASTER', 'CLUSTER_MASTER_NODE_NAME'},
    'nginx': {'NGINX_PORT', 'NGINX_CREDENTIALS'},
}
DEPENDENCIES = {
    'kibana': {'elasticsearch'}, 'nginx': {'kibana'},
    **{name: {'elasticsearch', 'kibana'} for name in (
        'packetbeat', 'filebeat', 'auditbeat', 'journalbeat',
        'heartbeat', 'metricbeat',
    )},
}
EXPOSED = {
    'wazuh': {'1514/udp', '1515/tcp', '514/udp', '55000/tcp'},
    'elasticsearch': {'9200/tcp'},
    'nginx': {'80/tcp', '443/tcp'},
}


def _environment_keys(value: object) -> set[str] | None:
    if value is None:
        return set()
    if isinstance(value, Mapping):
        return set(value)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return {v.split('=', 1)[0] for v in value}
    return None


def _names(value: object) -> set[str] | None:
    if value is None:
        return set()
    if isinstance(value, Mapping):
        return set(value)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return set(value)
    return None


def _expose(value: object) -> set[str] | None:
    if value is None:
        return set()
    if not isinstance(value, list):
        return None
    result = set()
    for item in value:
        if not isinstance(item, str):
            return None
        result.add(item if '/' in item else f'{item}/tcp')
    return result


def _source(value: str) -> str:
    """Normalize the harmless trailing slash Compose removes from bind paths."""
    return str(PurePosixPath(value))


def _mounts(service: Mapping) -> list[tuple[str, str, bool]] | None:
    found = []
    for volume in service.get('volumes', []):
        if not isinstance(volume, Mapping) or volume.get('type') != 'bind':
            return None
        source, target = volume.get('source'), volume.get('target')
        if not isinstance(source, str) or not isinstance(target, str):
            return None
        found.append((_source(source), target, volume.get('read_only') is True))
    return sorted(found)


def validate(model: object) -> list[str]:
    """Return safe-to-log failure descriptions; never print interpolated values."""
    errors = []
    if not isinstance(model, Mapping):
        return ['Compose output must be a JSON object']
    services = model.get('services')
    if not isinstance(services, Mapping):
        return ['Missing Compose services object']
    if set(services) != set(IMAGES):
        errors.append('Service inventory differs from the reviewed baseline')
    networks = model.get('networks')
    network = networks.get('sll_net') if isinstance(networks, Mapping) else None
    if not isinstance(network, Mapping) or network.get('external') is not True:
        errors.append('External sll_net contract changed')
    if isinstance(networks, Mapping) and set(networks) != {'sll_net'}:
        errors.append('Unexpected top-level network added')
    for name in IMAGES:
        service = services.get(name)
        if not isinstance(service, Mapping):
            errors.append(f'{name}: missing or invalid service')
            continue
        # Compose v5 normalizes absent commands/entrypoints into null fields.
        # Only that inert normalization is permitted; executable overrides fail.
        unexpected = set(service) - APPROVED_SERVICE_FIELDS - {'command', 'entrypoint'}
        if unexpected:
            errors.append(f"{name}: unreviewed service configuration fields ({', '.join(sorted(unexpected))})")
        if service.get('command') not in (None, [], ''):
            errors.append(f'{name}: unreviewed command override')
        if service.get('entrypoint') not in (None, [], ''):
            errors.append(f'{name}: unreviewed entrypoint override')
        if _environment_keys(service.get('environment')) != ENVIRONMENT_KEYS.get(
                name, set()):
            errors.append(f'{name}: environment variable contract changed')
        if _names(service.get('depends_on')) != DEPENDENCIES.get(name, set()):
            errors.append(f'{name}: service dependencies changed')
        if _expose(service.get('expose')) != EXPOSED.get(name, set()):
            errors.append(f'{name}: internal exposed ports changed')
        if service.get('image') != IMAGES[name]:
            errors.append(f'{name}: image or tag is not the reviewed baseline')
        if service.get('ports'):
            errors.append(f'{name}: host-published ports are prohibited')
        for forbidden in ('privileged', 'devices', 'network_mode', 'volumes_from',
                          'extra_hosts', 'group_add', 'sysctls', 'security_opt'):
            if service.get(forbidden):
                errors.append(f'{name}: unreviewed {forbidden} setting')
        caps = {str(cap).lower() for cap in service.get('cap_add', [])}
        if caps != CAPABILITIES.get(name, set()):
            errors.append(f'{name}: Linux capabilities changed')
        if service.get('pid') != ('host' if name == 'auditbeat' else None):
            errors.append(f'{name}: host PID contract changed')
        if service.get('user') != ('root' if name in ('filebeat', 'metricbeat') else None):
            errors.append(f'{name}: container user contract changed')
        assigned = service.get('networks')
        if (not isinstance(assigned, Mapping) or set(assigned) != {'sll_net'}
                or not isinstance(assigned['sll_net'], Mapping)
                or assigned['sll_net'].get('ipv4_address') != IP_ADDRESSES[name]):
            errors.append(f'{name}: network or fixed IP changed')
        expected = sorted((source, target, ro) for source, target, ro in MOUNTS[name])
        if _mounts(service) != expected:
            errors.append(f'{name}: bind-mount sources, targets, or modes changed')
    return errors


def main() -> int:
    try:
        model = json.load(sys.stdin)
    except (ValueError, UnicodeError):
        print('FAIL: Docker Compose did not produce valid JSON', file=sys.stderr)
        return 1
    failures = validate(model)
    for failure in failures:
        print(f'FAIL: {failure}', file=sys.stderr)
    if failures:
        return 1
    print(f'PASS: resolved Compose baseline ({len(IMAGES)} services; no deployment)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
