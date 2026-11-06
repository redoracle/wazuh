# Changelog

This project follows the Wazuh upstream stable release tags for its central components; the Compose packaging itself is independently maintained.

## Unreleased

- Rebuilt the single-node platform around Wazuh manager, indexer and dashboard **4.14.9**.
- Added release-aligned TLS certificate generation and configuration.
- Added a secure one-time credential initializer, generated bcrypt hashes and private host-only credentials.
- Limited default host exposure, removed auxiliary collectors and published indexer ports, and used managed named volumes.
- Added a comprehensive README, deployment/operations/upgrade documentation, security and contributor policies, and automated repository checks.

For upstream component changes, see [Wazuh Docker v4.14.9](https://github.com/wazuh/wazuh-docker/releases/tag/v4.14.9).

## Unreleased — optional AI-assisted operations

- Add evidence-based documentation of the self-hosted local LLM triage, security boundaries and operator acceptance requirements.
- Add opt-in, bounded read-only Wazuh Indexer alert triage CLI with metadata-only local Ollama inference, fail-closed security controls, per-run pseudonyms and minimal audit logs.
- Add independent Compose overlay with private AI model network and no additional host-published ports; base Wazuh 4.14.9 stack remains unchanged.
- Add setup, threat-model, operations, benchmark and rollback guides, plus offline security regression tests.

## Enterprise readiness gates (2026-11-06)

- Add explicit enterprise-not-ready classification, a read-only static/host preflight and 14 offline adversarial tests.
- Rotate Docker stdout/stderr logs, cap short-lived AI worker resources, and add architecture decision and runtime acceptance runbooks.
- Add a weekly non-mutating upstream stable-release watch, CODEOWNERS and deployment/supply-chain review checklist.
- Leave the Wazuh 4.14.9 release bundle, disk thresholds and enrollment semantics unchanged pending vendor-compatible staged validation.

## Enterprise security remediation in progress — November 2026

- Added password-authenticated Wazuh agent enrollment for **new installations**, a private bootstrap secret and a separate explicit migration path for previously initialized managers. Running containers are never automatically changed.
- Enabled single-data-node Indexer disk thresholds at low/high/flood 85/90/95, subject to staging verification and capacity/ingestion recovery tests.
- Added an isolated, plan-by-default snapshot helper and backup Compose overlay, with strict alert-index scoping and verification. Full off-host backup/restore still requires operator provisioning and evidence.
- Added pinned official multi-node inventory validation, read-only Docker runtime/GitHub governance probes, and a scheduled SHA-pinned Trivy image vulnerability scan. HA deployment, immutable image approval, branch protection and signed production acceptance remain gated.

- Improved test integrity with transactional first-run credential publication, caller-umask isolation, and strict existing audit-file permissions.
- Added local loopback TLS/API contracts, real generated X.509 fixtures, and effective Docker Compose policy verification; staged live Wazuh tests remain required.
