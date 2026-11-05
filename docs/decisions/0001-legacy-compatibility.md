# ADR 0001: Preserve legacy runtime behavior while adding quality gates

- **Status:** Accepted for the historical maintenance PR
- **Date:** 2026-11-05
- **Scope:** `docker-compose.yml`, tests, security and operator documentation

## Context

The repository contained only a 2019 Docker Compose file, a minimal README
and a license. The Compose file defines ten aging, tightly coupled images and
hard-coded host/network assumptions. There is no evidence of functional tests,
certificates, backup/restore procedures or a vendor-supported direct upgrade.
An unconditional image refresh could make old indices or integrations unusable.

## Decision

Preserve service names, fixed IPs, images and baseline tag defaults, host mount
targets, Linux capabilities, and host namespace access until a separate
version-aware migration has been tested. Permit clearly non-breaking cleanup:
remove Compose `links`, use explicit read-only mode for applicable collector
configuration inputs, pin offline tooling, and add a documented regression
contract and CI. Mark the stack **unsupported and unsuitable for production**.

Maintain immutable CI action references and local documentation/link checks.
Every proposed runtime-affecting change must state compatibility evidence,
service impact, how to observe failure, and how to restore the prior state.

## Consequences

- **Positive:** reproducible, auditable checks without starting vulnerable
  images; clear security boundaries; a smaller review surface for maintenance.
- **Negative:** existing public-range fixed IPs, legacy images, `/Datak` mounts,
  privileges, and lack of health checks remain. Static quality improvements
  do **not** remove these risks.
- **Follow-up:** a separate breaking change should replace the system with a
  supported Wazuh manager/indexer/dashboard deployment and test migration,
  TLS, persistence, backup, ingestion, least privilege and rollback.

Related: [architecture](../ARCHITECTURE.md), [security](../../SECURITY.md),
[upgrade plan](../UPGRADE.md), [operations](../OPERATIONS.md).
