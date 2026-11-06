"""Cryptographic contract checks using actual ephemeral CA and service certificates.

No signing key is committed. Everything is generated in a temporary directory
and destroyed after the suite. This tests the OpenSSL commands used by the gate,
not just mocked return codes.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import check_certificates as certificates


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is required for real certificate contract tests')
class RealCertificateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.path = Path(tmp.name)
        cls.path.chmod(0o700)
        cls.run_openssl([
            'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-keyout', 'root.key', '-out', 'root-ca.pem', '-days', '2',
            '-subj', '/CN=Wazuh test-only CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        ])
        shutil.copyfile(cls.path / 'root-ca.pem', cls.path / 'root-ca-manager.pem')
        for identity in ('admin', *certificates.SERVICES):
            cls.make_leaf(identity)
        for name in certificates.KEYS:
            (cls.path / name).chmod(0o600)

    @classmethod
    def run_openssl(cls, command):
        subprocess.run(['openssl', *command], cwd=cls.path, capture_output=True,
                       timeout=20, check=True)

    @classmethod
    def make_leaf(cls, identity):
        key = 'admin-key.pem' if identity == 'admin' else f'{identity}-key.pem'
        cert = f'{identity}.pem'
        csr = f'{identity}.csr'
        cls.run_openssl([
            'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-keyout', key, '-out', csr, '-subj', f'/CN={identity}',
        ])
        extension = cls.path / f'{identity}.ext'
        extension.write_text(f'subjectAltName=DNS:{identity}\n'
                             'basicConstraints=CA:FALSE\n'
                             'extendedKeyUsage=serverAuth,clientAuth\n')
        cls.run_openssl([
            'x509', '-req', '-in', csr, '-CA', 'root-ca.pem', '-CAkey', 'root.key',
            '-CAcreateserial', '-out', cert, '-days', '2', '-extfile', extension.name,
        ])

    def test_real_chain_hostnames_expiry_and_matching_keys_pass(self):
        results = certificates.inspect(self.path, min_days=1)
        self.assertTrue(results, 'No verification controls executed')
        self.assertTrue(all(results.values()), {k: v for k, v in results.items() if not v})
        for name in certificates.SERVICES:
            self.assertTrue(results[f'chain_and_hostname:{name}'])
            self.assertTrue(results[f'keypair_matches:{name}.pem'])

    def test_real_expiring_certificates_fail_required_headroom(self):
        results = certificates.inspect(self.path, min_days=30)
        self.assertFalse(results['certificate_valid_for_30d:root-ca.pem'])
        self.assertFalse(results['certificate_valid_for_30d:wazuh.indexer.pem'])

    def test_real_mismatched_key_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            target.chmod(0o700)
            for filename in (*certificates.CERTS, *certificates.KEYS):
                shutil.copyfile(self.path / filename, target / filename)
            shutil.copyfile(self.path / 'wazuh.manager-key.pem', target / 'wazuh.indexer-key.pem')
            for name in certificates.KEYS:
                (target / name).chmod(0o600)
            results = certificates.inspect(target, min_days=1)
            self.assertFalse(results['keypair_matches:wazuh.indexer.pem'])
            self.assertTrue(results['keypair_matches:wazuh.manager.pem'])

    def test_real_wrong_hostname_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d)
            target.chmod(0o700)
            for filename in (*certificates.CERTS, *certificates.KEYS):
                shutil.copyfile(self.path / filename, target / filename)
            shutil.copyfile(self.path / 'wazuh.manager.pem', target / 'wazuh.indexer.pem')
            for name in certificates.KEYS:
                (target / name).chmod(0o600)
            results = certificates.inspect(target, min_days=1)
            self.assertFalse(results['chain_and_hostname:wazuh.indexer'])
            self.assertTrue(results['chain_and_hostname:wazuh.manager'])
