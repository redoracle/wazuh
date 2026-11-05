# Contributing

Contributions are welcome for release alignment, documentation, security hardening and cross-platform compatibility.

## Development workflow

1. Open a focused issue or proposal for any architecture, exposure, credential or data-path change.
2. Create a feature branch from the repository default branch.
3. Use a Python 3.11+ virtual environment; `python -m pip install -r requirements-dev.txt`.
4. Run `python -m unittest discover -s tests -v` and `python -m compileall -q scripts tests`.
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
