"""Mutation tests of the effective Docker Compose security boundary."""
from __future__ import annotations

import copy
import unittest

from scripts.check_effective_compose import check, ComposePolicyError


def representative_model(ai=False):
    ports = lambda values: [
        {'target': target, 'published': published, 'host_ip': '127.0.0.1',
         'protocol': 'tcp'} for target, published in values
    ]
    services = {
        'wazuh.manager': {'ports': ports([(1514, '1514'), (1515, '1515'), (55000, '55000')]),
                          'networks': {'default': None}},
        'wazuh.indexer': {'networks': {'default': None}},
        'wazuh.dashboard': {'ports': ports([(5601, '443')]), 'networks': {'default': None}},
    }
    if ai:
        services['ai-triage'] = {'profiles': ['ai'], 'read_only': True,
                                 'cap_drop': ['ALL'], 'networks': {'default': None, 'ai-model-net': None}}
        services['ai-ollama'] = {'profiles': ['ai'], 'networks': {'ai-model-net': None}}
    return {'name': 'wazuh', 'services': services}


class EffectiveComposeTests(unittest.TestCase):
    def test_safe_resolved_base_and_ai_models_pass(self):
        self.assertEqual(check(representative_model())['result'], 'pass')
        self.assertTrue(check(representative_model(True), ai=True)['ai_profile_checked'])

    def test_env_interpolation_cannot_publish_manager_or_dashboard(self):
        for name in ('wazuh.manager', 'wazuh.dashboard'):
            model = representative_model()
            model['services'][name]['ports'][0]['host_ip'] = '0.0.0.0'
            with self.subTest(service=name), self.assertRaisesRegex(
                    ComposePolicyError, 'bind loopback'):
                check(model)

    def test_unexpected_indexer_publication_blocks(self):
        model = representative_model()
        model['services']['wazuh.indexer']['ports'] = [
            {'host_ip': '127.0.0.1', 'target': 9200, 'published': '9200'}]
        with self.assertRaisesRegex(ComposePolicyError, 'Unexpected host-published'):
            check(model)

    def test_model_connected_to_wazuh_network_blocks(self):
        model = representative_model(True)
        model['services']['ai-ollama']['networks']['default'] = None
        with self.assertRaisesRegex(ComposePolicyError, 'AI-only network'):
            check(model, ai=True)

    def test_extra_capabilities_and_socket_mount_block(self):
        for change in ({'privileged': True}, {'cap_add': ['SYS_ADMIN']},
                       {'pid': 'host'}, {'volumes': [{'source': '/var/run/docker.sock',
                                                     'target': '/var/run/docker.sock'}]}):
            model = representative_model()
            model['services']['wazuh.manager'].update(change)
            with self.subTest(change=change), self.assertRaises(ComposePolicyError):
                check(model)

    def test_unexpected_service_or_duplicate_port_blocks(self):
        model = representative_model()
        model['services']['evil'] = {}
        with self.assertRaisesRegex(ComposePolicyError, 'Unexpected service set'):
            check(model)
        model = representative_model()
        model['services']['wazuh.manager']['ports'].append(
            copy.deepcopy(model['services']['wazuh.manager']['ports'][0]))
        with self.assertRaisesRegex(ComposePolicyError, 'port inventory drift'):
            check(model)
