# Software supply chain and maintenance controls

## Exact version policy

- The three Wazuh central components are **one release set**. The repository intentionally pins them to stable **4.14.9**. A version bump requires configuration/certificate compatibility review and a separate PR, not a string-only upgrade.
- GitHub Actions dependencies are commit-SHA-pinned, and Python test/bootstrap dependencies use exact versions and Dependabot.
- **Container tags are not immutable**. Before enterprise use, approve the correct per-platform image digests, scan all images (manager, indexer, dashboard, certificate generator, Python worker and optional Ollama) and validate provenance/signatures according to your registry trust policy. The repository does **not** currently enforce digest pinning.
- Model blobs and licenses require separate review. A model tag, a successful download or local inference does not establish model integrity or accuracy.

## Continuous maintenance

The scheduled [upstream release monitor](../.github/workflows/upstream-release-watch.yml) compares the official Wazuh Docker *latest stable release* with the repository's declared release version. It reports drift; it **does not modify** image tags, generate changes, start containers or install pre-releases. This is advisory monitoring, **not** vulnerability scanning.

Run periodic container and Python dependency vulnerability scanning with your approved tooling; link findings to an accountable owner, severity, expiry and patch window. Apply environment-specific signatures and SBOM retention. Scan the host, Docker daemon and runtime config as separate assets. Keep a repeatable rollback artifact of the exact previous images, config and snapshots.

## Change gates

A version or image digest PR must include: vendor release note evidence, compatibility matrix, per-platform digests, scan/SBOM reports, TLS and Indexer compatibility, clean install results, staged migration and rollback, impact to agent versions, and a signed change approval. The main CI tests static contracts only. Production promotion requires the independent [acceptance protocol](PRODUCTION_ACCEPTANCE.md).
