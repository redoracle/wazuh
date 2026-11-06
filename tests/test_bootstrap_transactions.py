"""Black-box initialization invariants: no partial credentials on recoverable errors."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import io
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from scripts import bootstrap


class BootstrapTransactionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        template = self.root / 'config' / 'wazuh_cluster' / 'wazuh_manager.conf'
        template.parent.mkdir(parents=True)
        template.write_text('<cluster><key>{{CLUSTER_KEY}}</key></cluster>\n')
        (self.root / '.env.example').write_text(
            'DASHBOARD_BIND_ADDRESS=127.0.0.1\n'
            'AGENT_BIND_ADDRESS=127.0.0.1\n'
            'API_BIND_ADDRESS=127.0.0.1\n')
        patcher = patch.multiple(bootstrap, ROOT=self.root,
            ENV=self.root / '.env', EXAMPLE=self.root / '.env.example',
            GENERATED=self.root / 'config' / 'generated', MANAGER_TEMPLATE=template)
        patcher.start()
        self.addCleanup(patcher.stop)
        # Test publication and error-recovery independently from bcrypt's hash cost.
        users = patch.object(bootstrap, 'make_internal_users', return_value='_meta: {}\n')
        users.start()
        self.addCleanup(users.stop)

    def assert_no_partial_publication(self):
        self.assertFalse((self.root / '.env').exists())
        self.assertFalse((self.root / 'config' / 'generated').exists())
        self.assertFalse((self.root / '.bootstrap.lock').exists())
        self.assertEqual(list((self.root / 'config').glob('.bootstrap-*')), [])

    def test_failed_staged_write_does_not_publish_partial_credentials(self):
        original = bootstrap.write_secure
        def interrupted_write(path, content, mode):
            if path.name == 'wazuh.yml':
                raise OSError('injected failure during staging')
            return original(path, content, mode)

        with patch.object(bootstrap, 'write_secure', side_effect=interrupted_write):
            with self.assertRaisesRegex(OSError, 'during staging'):
                bootstrap.bootstrap()
        self.assert_no_partial_publication()
        with redirect_stdout(io.StringIO()):
            bootstrap.bootstrap()
        self.assertEqual(bootstrap.check_initialized(), [])
        self.assertEqual(stat.S_IMODE((self.root / '.env').stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.root / 'config' / 'generated').stat().st_mode), 0o700)
        self.assertFalse((self.root / 'config' / 'generated' / '.env.bootstrap').exists())

    def test_failed_final_publication_removes_staged_secrets(self):
        with patch.object(bootstrap.os, 'link', side_effect=OSError('injected publish failure')):
            with self.assertRaisesRegex(OSError, 'publish failure'):
                bootstrap.bootstrap()
        self.assert_no_partial_publication()

    def test_concurrent_initializer_lock_fails_closed_without_deleting_it(self):
        lock = self.root / '.bootstrap.lock'
        lock.write_text('owner marker')
        with self.assertRaises(FileExistsError):
            bootstrap.bootstrap()
        self.assertEqual(lock.read_text(), 'owner marker')
        self.assertFalse((self.root / '.env').exists())

    def test_existing_unrecognized_directory_is_never_overwritten(self):
        generated = self.root / 'config' / 'generated'
        generated.mkdir()
        (generated / 'operator-marker').write_text('KEEP')
        with self.assertRaisesRegex(RuntimeError, 'requires inspection'):
            bootstrap.bootstrap()
        self.assertEqual((generated / 'operator-marker').read_text(), 'KEEP')
        self.assertFalse((self.root / '.bootstrap.lock').exists())

    def test_second_run_preserves_all_initialized_credentials(self):
        with redirect_stdout(io.StringIO()):
            bootstrap.bootstrap()
        before = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in (self.root / '.env', *(self.root / 'config' / 'generated').iterdir())
        }
        with redirect_stdout(io.StringIO()) as result:
            bootstrap.bootstrap()
        self.assertIn('Already initialized', result.getvalue())
        after = {
            str(path.relative_to(self.root)): path.read_bytes()
            for path in (self.root / '.env', *(self.root / 'config' / 'generated').iterdir())
        }
        self.assertEqual(after, before)
