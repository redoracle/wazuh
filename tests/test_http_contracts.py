"""Real local HTTP(S) transport contracts without any live Wazuh dependency.

All servers bind to ephemeral loopback ports; certificates are generated per
suite with OpenSSL and tested through Python's real TLS validation. No proxy,
public DNS, cloud API, or external network access is involved.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from integrations.ai_triage import triage
from scripts import snapshot_guard as snapshot


class ContractHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.respond()

    def do_PUT(self):
        self.respond()

    def do_GET(self):
        self.respond()

    def respond(self):
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        self.server.requests.append({
            'method': self.command,
            'path': self.path,
            'authorization': self.headers.get('Authorization'),
            'body': body,
        })
        payload = self.server.payload
        self.send_response(self.server.status)
        self.send_header('Content-Type', 'application/json')
        if self.server.status in (301, 302, 303, 307, 308):
            self.send_header('Location', 'https://not-a-local-service.invalid/payload')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            # The client is expected to close early when refusing oversized data.
            pass

    def log_message(self, format, *args):
        pass


@contextmanager
def local_server(*, tls_context=None):
    server = ThreadingHTTPServer(('127.0.0.1', 0), ContractHandler)
    server.daemon_threads = True
    server.requests = []
    server.payload = b'{}'
    server.status = 200
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        scheme = 'https' if tls_context else 'http'
        yield server, f'{scheme}://127.0.0.1:{server.server_port}'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise AssertionError('Local integration server did not terminate')


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL is needed for real local TLS contract fixtures')
class TLSContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.path = Path(cls.temp.name)
        cls.cert = cls.path / 'localhost.pem'
        cls.key = cls.path / 'localhost-key.pem'
        command = [
            'openssl', 'req', '-x509', '-newkey', 'ec',
            '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', str(cls.key), '-out', str(cls.cert),
            '-days', '2', '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
        ]
        subprocess.run(command, check=True, capture_output=True, timeout=20)
        cls.untrusted_cert = cls.path / 'untrusted.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'ec',
            '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', str(cls.path / 'untrusted-key.pem'),
            '-out', str(cls.untrusted_cert), '-days', '2',
            '-subj', '/CN=untrusted',
        ], check=True, capture_output=True, timeout=20)
        cls.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.server_context.load_cert_chain(str(cls.cert), str(cls.key))

    def test_snapshot_create_uses_real_verified_tls_and_exact_safe_body(self):
        with local_server(tls_context=self.server_context) as (server, url):
            server.payload = b'{"accepted":true}'
            result = snapshot.api(url, '/_snapshot/offsite/wazuh-20261106t120000z',
                                  str(self.cert), 'snapshot-operator', 'synthetic-test-password',
                                  'PUT', snapshot.create_body(), 5)
            self.assertEqual(result, {'accepted': True})
            self.assertEqual(len(server.requests), 1)
            request = server.requests[0]
            self.assertEqual(request['method'], 'PUT')
            self.assertEqual(request['path'], '/_snapshot/offsite/wazuh-20261106t120000z')
            self.assertEqual(json.loads(request['body']), snapshot.create_body())
            auth = base64.b64decode(request['authorization'].removeprefix('Basic ')).decode('utf-8')
            self.assertEqual(auth, 'snapshot-operator:synthetic-test-password')

    def test_snapshot_rejects_wrong_ca_and_hostname_before_any_request(self):
        with local_server(tls_context=self.server_context) as (server, url):
            with self.assertRaisesRegex(snapshot.SnapshotError, 'Snapshot API request failed'):
                snapshot.api(url, '/_snapshot/offsite/name',
                             str(self.untrusted_cert),
                             'operator', 'not-a-secret', 'GET', None, 5)
            self.assertEqual(server.requests, [])

    def test_snapshot_denies_redirect_and_http_authorization_failure(self):
        with local_server(tls_context=self.server_context) as (server, url):
            server.status = 307
            with self.assertRaisesRegex(snapshot.SnapshotError, 'redirected unexpectedly'):
                snapshot.api(url, '/_snapshot/offsite/one', str(self.cert),
                             'operator', 'pw', 'GET', None, 5)
            server.status = 403
            with self.assertRaisesRegex(snapshot.SnapshotError, 'Snapshot API request failed'):
                snapshot.api(url, '/_snapshot/offsite/one', str(self.cert),
                             'operator', 'pw', 'GET', None, 5)
            self.assertEqual(len(server.requests), 2)

    def test_snapshot_fails_closed_on_oversized_and_malformed_responses(self):
        with local_server(tls_context=self.server_context) as (server, url):
            server.payload = b'{' + b'x' * snapshot.MAX_REPLY
            with self.assertRaisesRegex(snapshot.SnapshotError, 'size cap'):
                snapshot.api(url, '/_snapshot/offsite/one', str(self.cert),
                             'operator', 'pw', 'GET', None, 5)
            server.payload = b'{this-is-not-json}'
            with self.assertRaisesRegex(snapshot.SnapshotError, 'did not return JSON'):
                snapshot.api(url, '/_snapshot/offsite/one', str(self.cert),
                             'operator', 'pw', 'GET', None, 5)

    def test_indexer_fetch_uses_real_ca_verified_https_post_and_bounded_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_path = Path(tmp) / 'reader-password'
            password_path.write_text('synthetic-reader-password\n')
            password_path.chmod(0o600)
            with local_server(tls_context=self.server_context) as (server, url):
                server.payload = json.dumps({'hits': {'hits': [
                    {'_id': 'test-hit', '_source': {'rule': {'id': 42, 'level': 12}}}
                ]}}).encode('utf-8')
                # Host/port allowlist is tested independently; use the local
                # ephemeral server to exercise actual request and TLS behavior.
                with patch.object(triage, 'validate_url', return_value=url):
                    hits = triage.fetch_indexer(
                        url='https://wazuh.indexer:9200', ca_file=str(self.cert),
                        username='wazuh-ai-reader', password_file=str(password_path),
                        minutes=10, min_level=10, count=4, timeout=5)
                self.assertEqual(hits, [{'_id': 'test-hit', '_source': {'rule': {'id': 42, 'level': 12}}}])
                self.assertEqual(len(server.requests), 1)
                req = server.requests[0]
                self.assertEqual(req['method'], 'POST')
                self.assertEqual(req['path'], '/wazuh-alerts-4.x-*/_search')
                self.assertEqual(json.loads(req['body']), triage.search_query(10, 10, 4))
                self.assertEqual(base64.b64decode(req['authorization'][6:]).decode(),
                                 'wazuh-ai-reader:synthetic-reader-password')

    def test_indexer_rejects_bad_ca_without_exposing_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_path = Path(tmp) / 'password'
            password_path.write_text('unique-password-should-not-leak')
            password_path.chmod(0o600)
            with local_server(tls_context=self.server_context) as (server, url):
                with patch.object(triage, 'validate_url', return_value=url):
                    with self.assertRaises(triage.TriageError) as caught:
                        triage.fetch_indexer(
                            url='https://wazuh.indexer:9200', ca_file=str(self.untrusted_cert),
                            username='wazuh-ai-reader', password_file=str(password_path),
                            minutes=10, min_level=10, count=4, timeout=5)
                self.assertNotIn('unique-password-should-not-leak', str(caught.exception))
                self.assertEqual(server.requests, [])


class LocalModelHTTPContractTests(unittest.TestCase):
    def test_model_chat_reaches_only_local_api_and_untrusted_output_is_sanitized(self):
        with local_server() as (server, url):
            server.payload = json.dumps({'message': {'content': json.dumps({
                'summary': 'Review\n\x1b[31m now', 'confidence': 'certain',
                'hypotheses': ['Validate from primary evidence']})}}).encode('utf-8')
            with patch.object(triage, 'validate_url', return_value=url):
                result = triage.summarize_with_ollama(
                    [{'level': 12, 'rule_id': 100, 'agent_ref': 'pseudonym'}],
                    'qwen3:8b', 'http://ai-ollama:11434', 5)
            self.assertTrue(result['untrusted'])
            self.assertEqual(result['confidence'], 'unknown')
            self.assertNotIn('\n', result['summary'])
            self.assertNotIn('\x1b', result['summary'])
            self.assertEqual(server.requests[0]['path'], '/api/chat')
            data = json.loads(server.requests[0]['body'])
            self.assertEqual(data['model'], 'qwen3:8b')
            self.assertEqual(json.loads(data['messages'][1]['content'])['metadata_only'],
                             [{'level': 12, 'rule_id': 100, 'agent_ref': 'pseudonym'}])
            self.assertFalse(data['stream'])

    def test_invalid_model_json_is_refused(self):
        with local_server() as (server, url):
            server.payload = json.dumps({'message': {'content': '{broken'}}).encode('utf-8')
            with patch.object(triage, 'validate_url', return_value=url):
                with self.assertRaisesRegex(triage.TriageError, 'not valid JSON'):
                    triage.summarize_with_ollama([], 'qwen3:8b', 'http://ai-ollama:11434', 5)
