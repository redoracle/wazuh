# Contributing

Contributions are welcome for release alignment, documentation, security hardening and cross-platform compatibility.

## Development workflow

1. Open a focused issue or proposal for any architecture, exposure, credential or data-path change.
2. Create a feature branch from the repository default branch.
3. Use a Python 3.11+ virtual environment; `python -m pip install -r requirements-dev.txt`.
4. Run `python -m unittest discover -s tests -v` and `python -m compileall -q scripts tests integrations`; real TLS contract tests require OpenSSL.
5. For Compose changes, run `docker compose -f generate-indexer-certs.yml config --quiet` and `docker compose config --quiet` **after** a fresh local bootstrap; do not print secrets.
6. Submit a PR with the official Wazuh version or document reference, compatibility explanation, security and data impact, test evidence and rollback instructions.

Never commit `.env`, TLS private keys, `config/generated/`, real agent identifiers, customer logs or other secret material. Changes to the three Wazuh images, indexer schema and certificate generator **must be reviewed together** as a matched release update. Do not request a runtime test of internet-exposed endpoints from public CI.

A configuration-only test is not proof that services start correctly. Image and upgrade changes need a staging deployment with test ingestion, TLS verification, snapshots and restore. CI must pass before merge.

## Code and documentation conventions

- Use consistent YAML mappings, minimal container privileges, and pinned action/dependency versions.
- Keep deployment instructions reproducible and safe to run on a blank host.
- Validate links, explain host versus container ports, and document data-loss risks.
- Preserve Wazuh upstream copyright/attribution and the repository GPL-2.0 licensing obligations.

See [the security policy](SECURITY.md) for private vulnerability reports.

## AI integration changes

Any proposed AI adapter must preserve **no automatic Wazuh actions**, minimum-privilege identity, opt-in local processing, restricted egress, deterministic tests that inject malicious alert/model content, and human review. Do not add public MCP endpoints, remote-provider calls or API credentials to defaults. Update [AI evaluation](docs/AI_INTEGRATIONS.md), [threat model](docs/AI_SECURITY.md) and [acceptance tests](docs/AI_VALIDATION.md) with each change. Use `python -m unittest discover -s tests -v` and render the full Compose overlay before opening a PR.

## Change-management standard for self-hosted reliability

Run `make preflight` (after installing `requirements-dev.txt`), the Python unit suite, and the base and optional AI Compose validations. Do not claim enterprise availability without the [independent staging acceptance protocol](docs/PRODUCTION_ACCEPTANCE.md). Every change to topology, agent enrollment, networking, authentication, image versions, Indexer disk behavior or persistent volumes requires documented data-loss risks, vendor references, rollback and real staging test evidence.

For dependency updates, record exact third-party provenance and image digests as described in [supply-chain controls](docs/SUPPLY_CHAIN.md). Code owner review routing does not enforce approval until GitHub branch rules are configured.

## Test quality and evidence

See [Testing and validation](docs/TESTING.md). Never replace real TLS, response-schema or failure-path tests with a mocked network client and then claim integration coverage. New security-sensitive operations require a deterministic offline negative test and an operator acceptance case. Tests must be runnable in temporary directories and must not assume that an initialized operator checkout lacks `.env`.
