"""Adversarial contract tests for self-hosted readiness policy and maintenance."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_module(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = module
    assert spec.loader
    spec.loader.exec_module(module)
    return module


readiness = load_module('scripts/enterprise_preflight.py', 'enterprise_preflight')
releases = load_module('scripts/check_upstream_release.py', 'check_upstream_release')


class EnterprisePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('docker-compose.yml', 'docker-compose.ai.yml',
                     'config/wazuh_indexer/wazuh.indexer.yml',
                     'config/wazuh_cluster/wazuh_manager.conf'):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, dest)

    def findings(self, profile='controlled', host=False):
        return {item.control: item for item in readiness.evaluate(self.root, profile=profile, host=host)}

    def mutate(self, name: str, action):
        path = self.root / name
        data = yaml.safe_load(path.read_text(encoding='utf-8'))
        action(data)
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding='utf-8')

    def test_controlled_profile_passes_with_explicit_risks(self):
        results = self.findings()
        self.assertFalse([x for x in results.values() if x.result == 'block'])
        for name in ('disk_watermarks', 'immutable_images', 'enrollment_auth'):
            self.assertEqual(results[name].result, 'warn', name)

    def test_enterprise_profile_cannot_claim_production_readiness(self):
        results = self.findings('enterprise')
        for name in ('high_availability', 'snapshot_restore', 'live_acceptance',
                     'governance', 'network_policy', 'enrollment_auth', 'immutable_images'):
            self.assertEqual(results[name].result, 'block', name)

    def test_block_published_indexer(self):
        self.mutate('docker-compose.yml', lambda d: d['services']['wazuh.indexer'].update(ports=['9200:9200']))
        self.assertEqual(self.findings()['indexer_exposure'].result, 'block')

    def test_block_overly_broad_ports(self):
        self.mutate('docker-compose.yml', lambda d: d['services']['wazuh.manager'].update(ports=['0.0.0.0:1515:1515']))
        self.assertEqual(self.findings()['safe_port_defaults'].result, 'block')

    def test_block_privileged_worker_and_socket(self):
        self.mutate('docker-compose.ai.yml', lambda d: d['services']['ai-triage'].update(
            privileged=True, volumes=['/var/run/docker.sock:/var/run/docker.sock']))
        self.assertEqual(self.findings()['host_isolation'].result, 'block')

    def test_block_host_published_model(self):
        self.mutate('docker-compose.ai.yml', lambda d: d['services']['ai-ollama'].update(ports=['11434:11434']))
        self.assertEqual(self.findings()['ai_opt_in'].result, 'block')

    def test_block_unbounded_container_logs(self):
        self.mutate('docker-compose.yml', lambda d: d['services']['wazuh.dashboard'].pop('logging'))
        self.assertEqual(self.findings()['bounded_logs_wazuh.dashboard'].result, 'block')

    def test_duplicate_yaml_key_rejected(self):
        file = self.root / 'docker-compose.ai.yml'
        file.write_text(file.read_text(encoding='utf-8') + '\nservices:\n  unsafe: {}\n')
        with self.assertRaises(ValueError):
            self.findings()

    def test_block_component_release_drift(self):
        self.mutate('docker-compose.yml', lambda d: d['services']['wazuh.manager'].update(image='wazuh/wazuh-manager:latest'))
        self.assertEqual(self.findings()['release_bundle'].result, 'block')

    def test_runtime_host_check_never_reflects_secrets(self):
        secret = 'SENSITIVE_SUPER_SECRET_CONTENT'
        env = self.root / '.env'
        env.write_text('INDEXER_PASSWORD=' + secret + '\nAGENT_BIND_ADDRESS=0.0.0.0\n')
        env.chmod(0o600)
        results = self.findings(host=True)
        self.assertEqual(results['secret_file_permissions'].result, 'pass')
        self.assertEqual(results['runtime_host_exposure'].result, 'warn')
        self.assertNotIn(secret, json.dumps([vars(x) for x in results.values()]))

    def test_runtime_host_rejects_world_readable_secrets(self):
        env = self.root / '.env'
        env.write_text('INDEXER_PASSWORD=DUMMY\n')
        env.chmod(0o644)
        self.assertEqual(self.findings(host=True)['secret_file_permissions'].result, 'block')

    def test_host_generated_directory_rejects_world_search(self):
        generated = self.root / 'config/generated'
        generated.mkdir(parents=True)
        generated.chmod(0o755)
        self.assertEqual(self.findings(host=True)['generated_config_directory'].result, 'block')
        generated.chmod(0o700)
        self.assertEqual(self.findings(host=True)['generated_config_directory'].result, 'pass')

    def test_host_certificate_keys_missing_or_world_readable(self):
        cert_dir = self.root / 'config/wazuh_indexer_ssl_certs'
        cert_dir.mkdir(parents=True)
        self.assertEqual(self.findings(host=True)['certificate_private_key_access'].result, 'warn')
        for name in ('admin-key.pem', 'wazuh.indexer-key.pem',
                     'wazuh.manager-key.pem', 'wazuh.dashboard-key.pem'):
            target = cert_dir / name
            target.write_text('synthetic key')
            target.chmod(0o600)
        self.assertEqual(self.findings(host=True)['certificate_private_key_access'].result, 'pass')
        (cert_dir / 'admin-key.pem').chmod(0o644)
        self.assertEqual(self.findings(host=True)['certificate_private_key_access'].result, 'warn')

    def test_runtime_host_rejects_symlinked_secret(self):
        actual = self.root / 'private'
        actual.write_text('not printed')
        (self.root / '.env').symlink_to(actual)
        self.assertEqual(self.findings(host=True)['secret_file_permissions'].result, 'block')


class ReleaseMonitorTests(unittest.TestCase):
    def test_bundle_versions_must_match(self):
        content = (ROOT / 'docker-compose.yml').read_text()
        self.assertEqual(releases.current_version(content), '4.14.9')
        with self.assertRaises(ValueError):
            releases.current_version(content.replace('wazuh/wazuh-indexer:4.14.9', 'wazuh/wazuh-indexer:4.14.8'))

    def test_stable_release_parsing_and_pre_release_rejection(self):
        self.assertEqual(releases.latest_version({'tag_name': 'v4.14.10', 'prerelease': False}), '4.14.10')
        for metadata in ({'tag_name': 'v5.0.0-rc1', 'prerelease': True},
                         {'tag_name': 'v4.14.10', 'prerelease': True},
                         {'tag_name': '../../bad', 'prerelease': False}):
            with self.subTest(data=metadata), self.assertRaises(ValueError):
                releases.latest_version(metadata)

    def test_repository_docs_and_ownership(self):
        for file in ('docs/ENTERPRISE_READINESS.md', 'docs/PRODUCTION_ACCEPTANCE.md',
                     'docs/SUPPLY_CHAIN.md', 'docs/decisions/0001-controlled-single-node.md',
                     '.github/CODEOWNERS', '.github/workflows/upstream-release-watch.yml'):
            with self.subTest(file=file):
                self.assertTrue((ROOT / file).is_file())
        docs = (ROOT / 'docs/ENTERPRISE_READINESS.md').read_text()
        self.assertIn('NOT APPROVED', docs)
        self.assertIn('multi-node', docs)
        self.assertIn('snapshot', docs)


if __name__ == '__main__':
    unittest.main()
