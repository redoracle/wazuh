"""Offline attack-focused tests for changes addressing Wazuh enterprise readiness blockers."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

import yaml

from scripts import enrollment_security as enrollment
from scripts import snapshot_guard as snapshot
from scripts import validate_ha_inventory as ha
from scripts import runtime_probe as runtime
from scripts import check_github_governance as governance

ROOT = Path(__file__).resolve().parents[1]


class EnrollmentControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.g = self.root / 'config' / 'generated'
        self.g.mkdir(parents=True)
        self.g.chmod(0o700)
        self.manager = self.g / 'wazuh_manager.conf'
        self.manager.write_text('<ossec_config><auth><use_password>no</use_password></auth></ossec_config>')
        self.manager.chmod(0o644)

    def test_password_enrollment_is_explicit_idempotent_and_keeps_backup(self):
        self.assertIn('changes required', enrollment.prepare(self.root))
        self.assertFalse((self.g / 'authd.pass').exists())
        self.assertIn('configured', enrollment.prepare(self.root, apply=True))
        self.assertEqual((self.g / 'authd.pass').stat().st_mode & 0o777, 0o640)
        self.assertEqual(len((self.g / 'authd.pass').read_text().strip()), 64)
        self.assertIn(enrollment.TAG_YES, self.manager.read_text())
        self.assertIn(enrollment.TAG_NO, (self.g / 'wazuh_manager.conf.pre-enrollment').read_text())
        first = (self.g / 'authd.pass').read_text()
        self.assertIn('already enabled', enrollment.prepare(self.root, apply=True))
        self.assertEqual((self.g / 'authd.pass').read_text(), first)

    def test_symlinked_secret_and_open_directory_rejected(self):
        self.g.chmod(0o755)
        with self.assertRaises(ValueError):
            enrollment.prepare(self.root, apply=True)
        self.g.chmod(0o700)
        actual = self.root / 'existing'
        actual.write_text('secret')
        (self.g / 'authd.pass').symlink_to(actual)
        with self.assertRaises(ValueError):
            enrollment.prepare(self.root, apply=True)

    def test_enrollment_password_not_default_or_hardcoded(self):
        self.assertNotEqual(enrollment.new_password(), enrollment.new_password())
        compose = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
        self.assertIn('./config/generated/authd.pass:/var/ossec/etc/authd.pass:ro',
                      compose['services']['wazuh.manager']['volumes'])
        # The template must fail closed on new install.
        self.assertEqual((ROOT / 'config/wazuh_cluster/wazuh_manager.conf').read_text().count(enrollment.TAG_YES), 1)


class SnapshotSafetyTests(unittest.TestCase):
    def test_snapshot_request_omits_cluster_security_state(self):
        body = snapshot.create_body()
        self.assertEqual(body['indices'], 'wazuh-alerts-4.x-*')
        self.assertIs(body['include_global_state'], False)
        self.assertIs(body['partial'], False)
        self.assertFalse(body['ignore_unavailable'])

    def test_snapshot_identifiers_and_endpoint_cannot_be_redirected(self):
        for bad in ('../admin', 'a/b', 'bad?x=1', '.hidden', 'A Upper'):
            with self.subTest(value=bad), self.assertRaises(snapshot.SnapshotError):
                snapshot.safe_name(bad, 'wazuh-20261106t160000z')
        for url in ('http://wazuh.indexer:9200', 'https://evil.example.com:9200',
                    'https://wazuh.indexer:9200/evil', 'https://u:pass@wazuh.indexer:9200'):
            with self.subTest(url=url), self.assertRaises(snapshot.SnapshotError):
                snapshot.endpoint(url)

    def test_snapshot_untrusted_response_requires_success_no_shard_errors(self):
        name = 'wazuh-20261106t160000z'
        good = {'snapshots': [{'snapshot': name, 'state': 'SUCCESS', 'failures': [],
                               'shards': {'total': 3, 'failed': 0}, 'indices': ['wazuh-alerts-4.x-2026.11.06']}]}
        self.assertTrue(snapshot.successful_snapshot(good, name))
        for state in ('PARTIAL', 'IN_PROGRESS', 'FAILED'):
            bad = copy.deepcopy(good)
            bad['snapshots'][0]['state'] = state
            self.assertFalse(snapshot.successful_snapshot(bad, name))
        bad = copy.deepcopy(good)
        bad['snapshots'][0]['shards']['failed'] = 1
        self.assertFalse(snapshot.successful_snapshot(bad, name))

    def test_snapshot_plan_requires_no_network_or_secret(self):
        from contextlib import redirect_stdout
        import io
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(snapshot.main(['--repository', 'wazuh-offsite', '--mode', 'plan']), 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data['mode'], 'plan')
        self.assertTrue(data['operator_approval_required'])


class HADesignSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.example = json.loads((ROOT / 'deployments/ha/inventory.example.json').read_text())

    def test_valid_structure_is_not_treated_as_operational_approval(self):
        obj = ha.validate(self.example)
        self.assertEqual(obj['runtime_evidence'], 'NOT_CHECKED')
        self.assertEqual(obj['enterprise_approval'], 'NOT_GRANTED')

    def test_reject_same_host_or_failure_domain(self):
        for field in ('host', 'failure_domain'):
            doc = copy.deepcopy(self.example)
            doc['indexers'][1][field] = doc['indexers'][0][field]
            with self.subTest(field=field), self.assertRaises(ha.ArchitectureError):
                ha.validate(doc)

    def test_reject_missing_manager_backend(self):
        doc = copy.deepcopy(self.example)
        doc['agent_ingress']['backends'] = ['wazuh.master']
        with self.assertRaises(ha.ArchitectureError):
            ha.validate(doc)


class RuntimeAndSupplyChainTests(unittest.TestCase):
    def test_runtime_check_never_asserts_full_e2e(self):
        rows = [{'Service': s, 'State': 'running', 'Health': 'healthy'}
                for s in ('wazuh.manager', 'wazuh.indexer', 'wazuh.dashboard')]
        result = runtime.probe(runtime.parse_rows('\n'.join(map(json.dumps, rows))))
        self.assertTrue(result['running_contract'])
        for x in ('ingestion_tested', 'failover_tested', 'backup_restored', 'enterprise_approved'):
            self.assertFalse(result[x])
        rows[1]['Health'] = 'unhealthy'
        self.assertFalse(runtime.probe(rows)['running_contract'])

    def test_governance_requires_real_admin_enforcement(self):
        controls = {'required_status_checks': {'strict': True, 'contexts': sorted(governance.REQUIRED)},
                    'required_pull_request_reviews': {'required_approving_review_count': 1},
                    'enforce_admins': {'enabled': False},
                    'required_conversation_resolution': {'enabled': True}}
        self.assertEqual(governance.evaluate(controls)['status'], 'enterprise_governance_incomplete')
        controls['enforce_admins']['enabled'] = True
        self.assertEqual(governance.evaluate(controls)['status'], 'review_controls_present')
        self.assertFalse(governance.evaluate(controls)['full_enterprise_approval'])

    def test_reference_monitoring_rules_are_explicit_and_non_destructive(self):
        rules = yaml.safe_load((ROOT / 'monitoring/prometheus-rules.example.yml').read_text())
        groups = rules['groups']
        self.assertGreaterEqual(len(groups), 2)
        names = {rule['alert'] for group in groups for rule in group['rules']}
        self.assertIn('WazuhCoreTargetMissing', names)
        self.assertIn('WazuhDockerDataDiskCritical', names)
        self.assertIn('WazuhCoreMetricsAbsent', names)

    def test_scan_workflow_is_sha_pinned_and_covers_all_current_components(self):
        content = (ROOT / '.github/workflows/container-vulnerability-scan.yml').read_text()
        self.assertIn('aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25', content)
        self.assertIn("exit-code: '1'", content)
        for image in ('wazuh/wazuh-manager:4.14.9', 'wazuh/wazuh-indexer:4.14.9',
                      'wazuh/wazuh-dashboard:4.14.9', 'python:3.13-slim', 'ollama/ollama:0.40.15'):
            self.assertIn(image, content)


if __name__ == '__main__':
    unittest.main()
