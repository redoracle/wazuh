#!/usr/bin/env python3
"""Security-scoped, non-destructive OpenSearch/Wazuh alert snapshot trigger and verifier.

Requires a pre-provisioned off-host repository, least-privileged snapshot operator,
validated TLS and explicit --apply. Does NOT create repositories, restore or delete data.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

NAME = re.compile(r'^[a-z][a-z0-9_-]{2,62}$')
SNAPSHOT = re.compile(r'^wazuh-[0-9]{8}t[0-9]{6}z$')
MAX_REPLY = 256 * 1024
INDICES = 'wazuh-alerts-4.x-*'


class SnapshotError(Exception):
    """Safe operator-level diagnostic without upstream response bodies."""


def endpoint(raw: str) -> str:
    p = urllib.parse.urlsplit(raw)
    try:
        port = p.port
    except ValueError as e:
        raise SnapshotError('Invalid Indexer port') from e
    if (p.scheme != 'https' or not p.hostname or p.hostname not in ('wazuh.indexer', 'localhost', '127.0.0.1') or
            port != 9200 or p.path not in ('', '/') or p.username or p.password or p.query or p.fragment):
        raise SnapshotError('Only explicitly approved, CA-verified local Indexer endpoints are allowed')
    return 'https://' + p.hostname + ':9200'


def read_secret(path: str) -> str:
    p = Path(path)
    try:
        mode = p.lstat().st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) & 0o007 or p.stat().st_size > 256:
            raise SnapshotError('Credential file must be a private, bounded regular file')
        value = p.read_text(encoding='utf-8').strip('\r\n')
        if not value or len(value) > 200 or '\n' in value:
            raise SnapshotError('Invalid credential file')
        return value
    except (OSError, UnicodeError) as e:
        raise SnapshotError('Unable to read private snapshot credential') from e


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise SnapshotError('Snapshot API redirected unexpectedly')


def api(base: str, path: str, ca: str, username: str, password: str,
        method: str, body: dict | None, timeout: int) -> dict:
    try:
        context = ssl.create_default_context(cafile=ca)
    except (OSError, ValueError, ssl.SSLError) as e:
        raise SnapshotError("Unable to validate the trusted Indexer CA") from e
    token = base64.b64encode(f'{username}:{password}'.encode()).decode('ascii')
    request = urllib.request.Request(
        base + path,
        method=method,
        data=json.dumps(body, separators=(',', ':')).encode() if body is not None else None,
        headers={'Authorization': 'Basic ' + token, 'Content-Type': 'application/json', 'Accept': 'application/json'},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), RejectRedirect(), urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise SnapshotError('Snapshot API returned a non-success status')
            result = response.read(MAX_REPLY + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise SnapshotError('Snapshot API request failed; check TLS, repository and access policy') from e
    if len(result) > MAX_REPLY:
        raise SnapshotError('Snapshot API response exceeded size cap')
    try:
        obj = json.loads(result)
    except ValueError as e:
        raise SnapshotError('Snapshot API did not return JSON') from e
    if not isinstance(obj, dict):
        raise SnapshotError('Snapshot API returned unexpected shape')
    return obj


def safe_name(repo: str, name: str) -> tuple[str, str]:
    if not NAME.fullmatch(repo) or not SNAPSHOT.fullmatch(name):
        raise SnapshotError('Unsafe snapshot or repository identifier')
    return repo, name


def create_body() -> dict:
    # Do NOT include internal security state/cluster global state in routine alert snapshots.
    return {'indices': INDICES, 'ignore_unavailable': False, 'include_global_state': False, 'partial': False}


def successful_snapshot(obj: dict, name: str) -> bool:
    records = obj.get('snapshots')
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        return False
    entry = records[0]
    shards = entry.get('shards', {})
    return (entry.get('snapshot') == name and entry.get('state') == 'SUCCESS' and
            entry.get('failures') == [] and isinstance(shards, dict) and
            shards.get('failed') == 0 and isinstance(shards.get('total'), int) and shards['total'] > 0 and
            isinstance(entry.get('indices'), list) and
            any(x.startswith('wazuh-alerts-4.x-') for x in entry['indices'] if isinstance(x, str)))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=('plan', 'create', 'verify'), default='plan')
    p.add_argument('--apply', action='store_true', help='required for snapshot creation; no automatic restore')
    p.add_argument('--repository', required=True)
    p.add_argument('--snapshot', help='use a previously created snapshot name to verify it')
    p.add_argument('--url', default='https://wazuh.indexer:9200')
    p.add_argument('--ca-file')
    p.add_argument('--username')
    p.add_argument('--password-file')
    p.add_argument('--timeout', type=int, default=20)
    args = p.parse_args(argv)
    try:
        name = args.snapshot or ('wazuh-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dt%H%M%Sz'))
        repo, name = safe_name(args.repository, name)
        if not 2 <= args.timeout <= 60:
            raise SnapshotError('Timeout must be between 2 and 60 seconds')
        if args.mode == 'plan' or (args.mode == 'create' and not args.apply):
            print(json.dumps({'mode': 'plan', 'repository': repo, 'snapshot': name,
                              'indices': INDICES, 'global_state': False, 'partial': False,
                              'operator_approval_required': True}, sort_keys=True))
            return 0
        if args.mode == 'verify' and not args.snapshot:
            raise SnapshotError('--snapshot is required to verify an existing backup')
        if not all((args.ca_file, args.username, args.password_file)):
            raise SnapshotError('--ca-file, --username and --password-file are required for live calls')
        if not NAME.fullmatch(args.username):
            raise SnapshotError('Invalid snapshot operator username')
        base = endpoint(args.url)
        password = read_secret(args.password_file)
        path = '/_snapshot/' + repo + '/' + name
        if args.mode == 'create':
            response = api(base, path, args.ca_file, args.username, password, 'PUT', create_body(), args.timeout)
            if response.get('accepted') is not True and response.get('snapshot', {}).get('snapshot') != name:
                raise SnapshotError('Snapshot creation was not acknowledged')
            print(json.dumps({'mode': 'create', 'repository': repo, 'snapshot': name,
                              'status': 'accepted_not_verified', 'verify_before_signoff': True}, sort_keys=True))
        else:
            response = api(base, path, args.ca_file, args.username, password, 'GET', None, args.timeout)
            ok = successful_snapshot(response, name)
            print(json.dumps({'mode': 'verify', 'repository': repo, 'snapshot': name,
                              'status': 'success' if ok else 'not_successful',
                              'off_host_and_restore_still_required': True}, sort_keys=True))
            return 0 if ok else 3
        return 0
    except SnapshotError as e:
        print('Snapshot control: ' + str(e), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
