"""Mutation tests proving risky Compose configuration changes are detected."""

import copy
import unittest
from pathlib import Path

from scripts.validate_resolved_compose import IMAGES, MOUNTS, validate
from yaml_contract import load_yaml

ROOT = Path(__file__).resolve().parents[1]


def example_resolved_model():
    """Construct the expected Compose JSON shape without running Docker."""
    source = load_yaml(ROOT / 'docker-compose.yml')
    services = source['services']
    for name, service in services.items():
        service['image'] = IMAGES[name]
        volumes = []
        for volume in service.get('volumes', []):
            # Format: source:target[:ro], with absolute Unix paths only.
            parts = volume.split(':')
            volumes.append({
                'type': 'bind', 'source': parts[0], 'target': parts[1],
                'read_only': len(parts) == 3 and parts[2] == 'ro',
            })
        if volumes:
            service['volumes'] = volumes
    return source


class ResolvedComposeTests(unittest.TestCase):
    def setUp(self):
        self.model = example_resolved_model()

    def test_passes_reviewed_baseline(self):
        self.assertFalse(validate(self.model))
        self.assertEqual(len(MOUNTS), len(IMAGES))

    def test_rejects_unreviewed_command_or_environment(self):
        self.model['services']['nginx']['entrypoint'] = ['/bin/sh', '-c', 'echo bad']
        self.model['services']['nginx']['environment'].append('DOCKER_HOST=tcp://host')
        errors = validate(self.model)
        self.assertTrue(any('unreviewed entrypoint override' in e for e in errors))
        self.assertTrue(any('environment variable contract' in e for e in errors))

    def test_allows_compose_normalized_empty_command_and_entrypoint(self):
        for service in self.model['services'].values():
            service['command'] = None
            service['entrypoint'] = None
        self.assertFalse(validate(self.model))

    def test_rejects_new_dependency_or_exposed_port(self):
        self.model['services']['nginx']['depends_on'].append('wazuh')
        self.model['services']['nginx']['expose'].append('2375')
        errors = validate(self.model)
        self.assertTrue(any('dependencies changed' in e for e in errors))
        self.assertTrue(any('internal exposed ports changed' in e for e in errors))

    def test_rejects_new_public_listener(self):
        self.model['services']['nginx']['ports'] = [{'published': '443'}]
        self.assertIn('nginx: host-published ports are prohibited',
                      validate(self.model))

    def test_rejects_new_privileged_container(self):
        self.model['services']['kibana']['privileged'] = True
        self.assertTrue(any('unreviewed privileged' in e for e in validate(self.model)))

    def test_rejects_unreviewed_extra_socket_mount(self):
        self.model['services']['kibana']['volumes'].append({
            'type': 'bind', 'source': '/var/run/docker.sock',
            'target': '/var/run/docker.sock', 'read_only': True,
        })
        self.assertTrue(any('kibana: bind-mount' in e for e in validate(self.model)))

    def test_rejects_writable_sensitive_config(self):
        volumes = self.model['services']['filebeat']['volumes']
        next(v for v in volumes if v['target'] == '/etc/filebeat/filebeat.yml')[
            'read_only'] = False
        self.assertTrue(any('filebeat: bind-mount' in e for e in validate(self.model)))

    def test_rejects_unreviewed_image_tag_and_network(self):
        self.model['services']['wazuh']['image'] = 'wazuh/wazuh:latest'
        self.model['services']['wazuh']['networks']['sll_net'][
            'ipv4_address'] = '0.0.0.0'
        failures = validate(self.model)
        self.assertTrue(any('image or tag' in e for e in failures))
        self.assertTrue(any('network or fixed IP' in e for e in failures))

    def test_rejects_unexpected_service_and_network(self):
        self.model['services']['other'] = copy.deepcopy(
            self.model['services']['kibana'])
        self.model['networks']['insecure'] = {'external': True}
        failures = validate(self.model)
        self.assertTrue(any('Service inventory' in e for e in failures))
        self.assertTrue(any('Unexpected top-level network' in e for e in failures))

    def test_rejects_host_pid_and_expanded_capabilities(self):
        self.model['services']['nginx']['pid'] = 'host'
        self.model['services']['nginx']['cap_add'] = ['SYS_ADMIN']
        failures = validate(self.model)
        self.assertTrue(any('nginx: host PID' in e for e in failures))
        self.assertTrue(any('nginx: Linux capabilities' in e for e in failures))

    def test_rejects_non_mapping_and_missing_services(self):
        self.assertTrue(validate({}))
        self.assertTrue(validate([]))
        del self.model['services']['nginx']
        self.assertTrue(any('nginx: missing' in e for e in validate(self.model)))


if __name__ == '__main__':
    unittest.main()
