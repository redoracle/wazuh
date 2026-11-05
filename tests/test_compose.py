"""Offline regression checks for the historical stack contract."""
import ipaddress
import re
import unittest
from pathlib import Path

from yaml_contract import load_yaml

ROOT = Path(__file__).resolve().parents[1]
SERVICES = {
    'wazuh', 'elasticsearch', 'kibana', 'nginx', 'packetbeat', 'filebeat',
    'auditbeat', 'journalbeat', 'heartbeat', 'metricbeat',
}
WAZUH = {'wazuh', 'elasticsearch', 'kibana', 'nginx'}
EXACT_IPS = {
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


class ComposeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
        cls.compose = load_yaml(ROOT / 'docker-compose.yml')
        cls.services = cls.compose['services']

    def test_service_inventory_and_legacy_contract(self):
        self.assertEqual(set(self.services), SERVICES)
        self.assertEqual(self.compose['networks']['sll_net']['external'], True)
        self.assertNotIn('version', self.compose)
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertNotIn('links', service)
                self.assertNotIn('ports', service)  # no new host-facing endpoints
                self.assertTrue(set(service.get('depends_on', [])) <= SERVICES)

    def test_pinned_compatible_image_family_defaults(self):
        for name, service in self.services.items():
            expected = ('${WAZUH_STACK_TAG:-3.10.2_7.3.2}' if name in WAZUH
                        else '${BEATS_TAG:-7.4.2}')
            image = service['image']
            with self.subTest(service=name):
                self.assertTrue(image.endswith(':' + expected), image)
                repo = ('wazuh/wazuh' if name == 'wazuh'
                        else 'wazuh/wazuh-' + name if name in WAZUH
                        else 'docker.elastic.co/beats/' + name)
                self.assertEqual(image.split(':')[0], repo)
                self.assertNotIn(':latest', image)

    def test_address_contract_and_uniqueness(self):
        ips = [ipaddress.ip_address(s['networks']['sll_net']['ipv4_address'])
               for s in self.services.values()]
        self.assertEqual(len(set(ips)), len(SERVICES))
        # These public-range IPs are intentionally preserved for compatibility,
        # NOT recommended for new deployments; see SECURITY.md.
        self.assertEqual(
            {name: service['networks']['sll_net']['ipv4_address']
             for name, service in self.services.items()}, EXACT_IPS
        )
        self.assertFalse(any(ip.is_private for ip in ips))

    def test_read_only_journal_and_collector_config(self):
        for mount in (
            '/run/log/journal:/var/log/journal:ro',
            '/run/systemd:/run/systemd:ro',
            '/etc/machine-id:/etc/machine-id:ro',
        ):
            self.assertIn(mount, self.services['journalbeat']['volumes'])
        for name in ('filebeat', 'auditbeat', 'metricbeat'):
            configs = [v for v in self.services[name]['volumes']
                       if '/etc/' + name + '/' in v]
            self.assertEqual(len(configs), 1)
            self.assertTrue(configs[0].endswith(':ro'))
        self.assertIn('/var/run/docker.sock:/var/run/docker.sock:ro',
                      self.services['filebeat']['volumes'])

    def test_ci_actions_are_immutable_and_permissions_are_minimal(self):
        workflow = (ROOT / '.github/workflows/validate.yml').read_text()
        self.assertIn('permissions:\n  contents: read', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertRegex(workflow, r'actions/checkout@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+')
        self.assertRegex(workflow, r'actions/setup-python@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+')

    def test_host_privilege_contract_is_not_expanded(self):
        expected_caps = {
            'packetbeat': {'NET_RAW', 'NET_ADMIN'},
            'auditbeat': {'AUDIT_CONTROL', 'AUDIT_READ'},
            'metricbeat': {'dac_read_search', 'sys_ptrace'},
        }
        for name, service in self.services.items():
            with self.subTest(service=name):
                self.assertNotIn('privileged', service)
                self.assertNotIn('network_mode', service)
                self.assertNotIn('devices', service)
                self.assertEqual(set(service['networks']), {'sll_net'})
                self.assertEqual(set(service.get('cap_add', [])),
                                 expected_caps.get(name, set()))
                self.assertEqual(service.get('pid'),
                                 'host' if name == 'auditbeat' else None)
                self.assertEqual(service.get('user'),
                                 'root' if name in {'filebeat', 'metricbeat'}
                                 else None)

    def test_docker_socket_access_is_not_expanded(self):
        actual_users = {
            name for name, service in self.services.items()
            if any('/var/run/docker.sock:' in vol
                   for vol in service.get('volumes', []))
        }
        self.assertEqual(actual_users, {'filebeat', 'metricbeat'})
        for name in actual_users:
            self.assertIn('/var/run/docker.sock:/var/run/docker.sock:ro',
                          self.services[name]['volumes'])

    def test_legacy_data_mount_targets_remain_explicit(self):
        # These targets are NOT confirmed correct persistence directories.
        # Preserving them is a compatibility decision, not an endorsement.
        expected = {
            'elasticsearch': 'Elasticsearch', 'kibana': 'Kibana',
            'nginx': 'Nginx', 'filebeat': 'Filebeat',
            'auditbeat': 'Auditbeat', 'journalbeat': 'Journalbeat',
            'heartbeat': 'Heartbeat', 'metricbeat': 'Metricbeat',
        }
        for name, directory in expected.items():
            with self.subTest(service=name):
                suffix = '/' if name in {'filebeat', 'auditbeat', 'metricbeat'} else ''
                expected_mount = f'/DATA/Wazuh/{directory}{suffix}:/Datak'
                self.assertIn(expected_mount, self.services[name]['volumes'])

    def test_env_example_and_fallbacks(self):
        example = (ROOT / '.env.example').read_text(encoding='utf-8')
        for var, version in [('WAZUH_STACK_TAG', '3.10.2_7.3.2'),
                             ('BEATS_TAG', '7.4.2')]:
            self.assertRegex(example, rf'(?m)^{var}={re.escape(version)}$')
            self.assertIn('${' + var + ':-' + version + '}', self.raw)
        self.assertRegex(example, r'(?m)^NGINX_CREDENTIALS=$')


if __name__ == '__main__':
    unittest.main()
