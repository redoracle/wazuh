"""Offline adversarial checks for documentation and certificate operator gates."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(rel: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    assert spec and spec.loader
    obj = importlib.util.module_from_spec(spec)
    sys.modules[name] = obj
    spec.loader.exec_module(obj)
    return obj


docs = module('scripts/check_docs.py', 'wazuh_check_docs')
certs = module('scripts/check_certificates.py', 'wazuh_check_certificates')


class DocumentationTests(unittest.TestCase):
    def test_entire_repository_has_no_broken_local_links(self):
        self.assertEqual(docs.check(ROOT), [])

    def test_heading_slug_normalizes_inline_code(self):
        self.assertEqual(docs.github_slug('Credential `rotation` & recovery'), 'credential-rotation--recovery')
        self.assertEqual(docs.anchors('# Hello\n# Hello\n'), {'hello', 'hello-1'})

    def test_detects_missing_local_target_and_fragment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'README.md').write_text('# Introduction\n[bad](does-not-exist.md)\n[fragment](#not-here)\n')
            errors = docs.check(root)
            self.assertEqual(len(errors), 2)
            self.assertIn('missing local file', errors[0])
            self.assertIn('missing heading', errors[1])

    def test_rejects_directory_traversal_and_ignores_fenced_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'README.md').write_text('````md\n[ignore](missing.md)\n````\n[external](https://example.org/x)\n[escape](../outside.md)\n')
            errors = docs.check(root)
            self.assertEqual(len(errors), 1)
            self.assertIn('escapes repository', errors[0])


class CertificateTests(unittest.TestCase):
    def make_cert_tree(self, directory: Path):
        directory.chmod(0o700)
        for name in (*certs.CERTS, *certs.KEYS):
            path = directory / name
            path.write_text('TEST CERTIFICATE PLACEHOLDER')
            path.chmod(0o600)

    def test_complete_certificates_with_mocked_valid_openssl(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.make_cert_tree(directory)
            with patch.object(certs.shutil, 'which', return_value='/usr/bin/openssl'), \
                 patch.object(certs, 'openssl_ok', return_value=True) as check, \
                 patch.object(certs, 'matching_key_pair', return_value=True):
                findings = certs.inspect(directory)
            self.assertTrue(all(findings.values()), findings)
            self.assertGreaterEqual(check.call_count, 10)

    def test_rejects_missing_or_world_readable_private_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.make_cert_tree(directory)
            key = directory / certs.KEYS[0]
            key.chmod(0o644)
            with patch.object(certs.shutil, 'which', return_value='/usr/bin/openssl'), \
                 patch.object(certs, 'openssl_ok', return_value=True), \
                 patch.object(certs, 'matching_key_pair', return_value=True):
                self.assertFalse(certs.inspect(directory)[f'private_key_permissions:{key.name}'])
                key.unlink()
                key.symlink_to(directory / certs.KEYS[1])
                self.assertFalse(certs.inspect(directory)[f'private_key_permissions:{key.name}'])

    def test_certificate_directory_must_restrict_other_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            directory.chmod(0o755)
            with patch.object(certs.shutil, 'which', return_value=None):
                findings = certs.inspect(directory)
            self.assertFalse(findings['certificate_directory_private'])
            self.assertFalse(findings['openssl_available'])

    def test_bad_expiry_is_visible_without_certificate_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.make_cert_tree(directory)
            with patch.object(certs.shutil, 'which', return_value='/usr/bin/openssl'), \
                 patch.object(certs, 'openssl_ok', return_value=False), \
                 patch.object(certs, 'matching_key_pair', return_value=False):
                findings = certs.inspect(directory)
            self.assertFalse(findings['certificate_valid_for_30d:root-ca.pem'])
            self.assertNotIn('TEST CERTIFICATE PLACEHOLDER', str(findings))

    def test_mismatched_certificate_and_key_block_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.make_cert_tree(directory)
            with patch.object(certs.shutil, 'which', return_value='/usr/bin/openssl'), \
                 patch.object(certs, 'openssl_ok', return_value=True), \
                 patch.object(certs, 'matching_key_pair', return_value=False):
                results = certs.inspect(directory)
            self.assertFalse(results['keypair_matches:admin.pem'])
            self.assertFalse(all(results.values()))

    def test_expiry_bounds_are_enforced(self):
        with self.assertRaises(ValueError):
            certs.inspect(min_days=-1)
        with self.assertRaises(ValueError):
            certs.inspect(min_days=3651)


if __name__ == '__main__':
    unittest.main()
