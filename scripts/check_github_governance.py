#!/usr/bin/env python3
"""Read-only GitHub master-branch governance assessment. Never changes repository rules.

A GitHub token with repo admin *read* permission may be required. No token is logged.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

REPO = 'redoracle/wazuh'
REQUIRED = {'Python and bootstrap contracts (3.11)',
            'Python and bootstrap contracts (3.13)',
            'Python and bootstrap contracts (3.14)',
            'Docker Compose configuration'}


def evaluate(protection: dict) -> dict:
    status = protection.get('required_status_checks') or {}
    checks = status.get('contexts') or []
    for check in status.get('checks') or []:
        if isinstance(check, dict) and isinstance(check.get('context'), str):
            checks.append(check['context'])
    reviews = protection.get('required_pull_request_reviews') or {}
    approved = (status.get('strict') is True and REQUIRED.issubset(set(checks)) and
                reviews.get('required_approving_review_count', 0) >= 1 and
                protection.get('enforce_admins', {}).get('enabled') is True and
                protection.get('required_conversation_resolution', {}).get('enabled') is True)
    return {'status': 'review_controls_present' if approved else 'enterprise_governance_incomplete',
            'required_checks_match': REQUIRED.issubset(set(checks)),
            'reviews_required': reviews.get('required_approving_review_count', 0) >= 1,
            'strict_checks': status.get('strict') is True,
            'admins_subject_to_checks': protection.get('enforce_admins', {}).get('enabled') is True,
            'review_threads_required': protection.get('required_conversation_resolution', {}).get('enabled') is True,
            'full_enterprise_approval': False}


def main() -> int:
    url = f'https://api.github.com/repos/{REPO}/branches/master/protection'
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'wazuh-readonly-governance-audit'}
    token = os.getenv('GH_TOKEN')
    if token:
        headers['Authorization'] = 'Bearer ' + token
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=10) as response:
            body = response.read(128000)
        report = evaluate(json.loads(body))
        print(json.dumps(report, sort_keys=True))
        return 0 if report['status'] == 'review_controls_present' else 3
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        print(json.dumps({'status': 'unverified_or_unprotected', 'full_enterprise_approval': False}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
