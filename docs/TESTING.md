# Test architecture and evidence policy

This repository distinguishes **source contracts**, **local component integration**, and **production acceptance**. A passing GitHub Actions workflow is not proof that live Wazuh telemetry, enrollment, AI inference, Indexer snapshots or HA failover work.

## Layers and commands

| Layer | Entry point | Evidence | Limit |
| --- | --- | --- | --- |
| Deterministic policy/unit | `python -m unittest discover -s tests -v` | Configuration validation, redaction, failure handling, staging and idempotency | No live Wazuh components |
| Local HTTP(S) contracts | `python -m unittest discover -s tests -p 'test_http_contracts.py' -v` | Real loopback transport, TLS CA trust, HTTP status/redirect/body limits, Indexer search and model chat payloads | Synthetic servers, not real API authorization |
| Real X.509 checks | `python -m unittest discover -s tests -p 'test_real_certificates.py' -v` | Temporary CA, signed service certificates, SAN, expiry, key mismatch | Test keys and certificates are not deployment material |
| Effective Compose | `docker compose -f docker-compose.yml config --format json \| python scripts/check_effective_compose.py` | Interpolated loopback ports, privileged host resources and exact base service set | No running containers or firewall assurance |
| Effective AI overlay | `docker compose -f docker-compose.yml -f docker-compose.ai.yml config --format json \| python scripts/check_effective_compose.py --ai` | Model network isolation and opt-in worker boundary | Does not establish real container network isolation |
| Staging acceptance | [Production acceptance](PRODUCTION_ACCEPTANCE.md) | Real enrollment rejection/acceptance, ingestion, Indexer RBAC, tested snapshots and restore | Requires external host and operator evidence |

Create an isolated Python 3.11+ virtual environment, install `requirements-dev.txt` and ensure OpenSSL is available. Run the commands from the repository root. Docker Compose model checks require **generated test credentials** from `python scripts/bootstrap.py` in a disposable checkout; never run bootstrap against existing deployment volumes merely to satisfy CI.

**Do not use `docker compose config` without a pipe into an approved local consumer when handling actual credentials.** Resolved service environments include secrets. CI pipes JSON only into the read-only policy checker, which emits a compact pass/fail report without recording the payload. Never attach resolved Compose output, `.env`, private keys or real alerts to CI artifacts.

## Reliability and anti-flakiness rules

- Use a fixed UTC clock and test-only deterministic pseudonymization keys for offline fixtures; do not use current time to decide whether a test alert should match.
- Test bootstrap in isolated temporary checkout fixtures; no test may assume `.env` is absent in an operator's genuine working directory.
- Run local transport tests on ephemeral `127.0.0.1` ports. No external DNS or public API should be contacted by a pull-request test.
- Use real test-generated X.509 certificates in certificate acceptance tests, and preserve negative CA/hostname/key-mismatch checks. OpenSSL must be present on CI runners.
- Treat password secret contents as toxic test output: no access tokens, Basic credentials or Compose secrets in failure text or artifacts.
- Assert both a precise error and absence of partial state for failure injection. Avoid mocks at network and crypto boundaries if local in-process test servers can exercise them.
- Keep unit checks independent of user environment and global process state (umask, current working directory, environment, `sys.path`, timezone).

## First-run initialization failure behavior

`scripts/bootstrap.py` serializes cooperating invocations using `.bootstrap.lock`, stages generated files in a private `config/.bootstrap-*` directory and publishes `.env` last. An ordinary exception while staging or publishing cleans up material written by the failed attempt. Existing initialized credentials are not rotated. **A hard power loss or `SIGKILL` is not transactional across filesystems** and can leave ignored staging files or a stale lock. Operators should inspect and securely dispose of abandoned material only after confirming no initializer is running, and should not delete an active deployment's `.env` or `config/generated/`.

## Operational release gates still outside CI

Before authorizing an enterprise rollout, provide dated, sanitized staging evidence for: a running Wazuh manager/indexer/dashboard; authenticated and rejected agent enrollment; a synthetic known event indexed and searchable; denied and permitted AI-reader queries; TLS chain and identity checks against deployed services; isolated off-host snapshot and full restore; disk-full recovery; and multi-host failover/quorum under node loss. Attach redacted evidence and measured RPO/RTO to the approved change record, not the repository.

An offline green suite cannot waive any of these gates. See [Enterprise readiness](ENTERPRISE_READINESS.md) and [Backup and restore](BACKUP_RESTORE.md).
