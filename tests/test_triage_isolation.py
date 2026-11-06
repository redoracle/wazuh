"""Deterministic CLI behavior and protected audit-log state."""
from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from integrations.ai_triage import triage


class TriageIsolationTests(unittest.TestCase):
    NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)

    def test_complete_offline_report_has_fixed_metadata_and_no_secret(self):
        record = {'timestamp': (self.NOW - timedelta(minutes=1)).isoformat(),
                  'rule': {'id': '100123', 'level': 13, 'groups': ['authentication_failed'],
                           'mitre': {'id': ['T1110']}},
                  'agent': {'id': '002', 'name': 'hidden-host'},
                  'full_log': 'password=my-private-value',
                  'data': {'srcip': '10.20.30.40'}}
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'alerts.jsonl'
            source.write_text(json.dumps(record) + '\n')
            stdout = io.StringIO()
            with (patch.object(triage, 'utcnow', return_value=self.NOW),
                  patch.object(triage.secrets, 'token_bytes', return_value=b'k' * 32),
                  patch.object(triage, 'send_json', side_effect=AssertionError('No network permitted')),
                  redirect_stdout(stdout)):
                rc = triage.cli(['--source', 'file', '--input-file', str(source)])
            self.assertEqual(rc, 0)
            output = json.loads(stdout.getvalue())
            expected = hmac.new(b'k' * 32, b'002', hashlib.sha256).hexdigest()[:12]
            self.assertEqual(output['alerts'], [{'timestamp': record['timestamp'],
                'level': 13, 'rule_id': 100123, 'groups': ['authentication_failed'],
                'mitre_ids': ['T1110'], 'agent_ref': expected}])
            self.assertEqual(output['advisory']['provider'], 'none')
            self.assertTrue(output['human_review_required'])
            for private in ('my-private-value', 'hidden-host', '10.20.30.40'):
                self.assertNotIn(private, stdout.getvalue())

    @unittest.skipUnless(os.name == 'posix', 'POSIX umask contract')
    def test_cli_does_not_modify_caller_umask(self):
        old = os.umask(0o027)
        try:
            with tempfile.TemporaryDirectory() as d:
                source = Path(d) / 'input.jsonl'
                source.write_text('{}\n')
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(triage.cli(['--input-file', str(source)]), 0)
            current = os.umask(0o027)
            self.assertEqual(current, 0o027)
        finally:
            os.umask(old)

    @unittest.skipUnless(os.name == 'posix', 'POSIX credential file mode contract')
    def test_world_readable_reader_secret_is_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as d:
            password = Path(d) / 'ai-reader-password'
            password.write_text('private-test-token')
            password.chmod(0o644)
            ca = Path(d) / 'ca.pem'
            ca.write_text('unused-fixture')
            with patch.object(triage, 'send_json', side_effect=AssertionError('No request allowed')):
                with self.assertRaisesRegex(triage.TriageError, 'group/world accessible'):
                    triage.fetch_indexer(
                        url='https://wazuh.indexer:9200', ca_file=str(ca),
                        username='wazuh-ai-reader', password_file=str(password),
                        minutes=15, min_level=10, count=1, timeout=5)

    def test_existing_world_readable_audit_file_is_rejected_without_append(self):
        with tempfile.TemporaryDirectory() as d:
            audit_path = Path(d) / 'audit.jsonl'
            audit_path.write_text('KEEP\n')
            audit_path.chmod(0o644)
            with self.assertRaisesRegex(triage.TriageError, 'owner-only'):
                triage.audit(str(audit_path), source='file', count=1, ollama=False, status='ok')
            self.assertEqual(audit_path.read_text(), 'KEEP\n')

    def test_hardlinked_audit_file_is_rejected_without_append(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'log'
            original.write_text('KEEP\n')
            original.chmod(0o600)
            linked = Path(d) / 'alias'
            os.link(original, linked)
            with self.assertRaisesRegex(triage.TriageError, 'hard links'):
                triage.audit(str(linked), source='file', count=1, ollama=False, status='ok')
            self.assertEqual(original.read_text(), 'KEEP\n')
