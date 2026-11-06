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

- Add independent research comparison of Wazuh Cloud AI Analyst, MCP integrations, local LLMs and SOC orchestration.
- Add opt-in, bounded read-only Wazuh Indexer alert triage CLI with metadata-only local Ollama inference, fail-closed security controls, per-run pseudonyms and minimal audit logs.
- Add independent Compose overlay with private AI model network and no additional host-published ports; base Wazuh 4.14.9 stack remains unchanged.
- Add setup, threat-model, operations, benchmark and rollback guides, plus offline security regression tests.
