# Software supply chain and maintenance controls

## Exact version policy

- The three Wazuh central components are **one release set**. The repository intentionally pins them to stable **4.14.9**. A version bump requires configuration/certificate compatibility review and a separate PR, not a string-only upgrade.
- GitHub Actions dependencies are commit-SHA-pinned, and Python test/bootstrap dependencies use exact versions and Dependabot.
- **Container tags are not immutable**. Before enterprise use, approve the correct per-platform image digests, scan all images (manager, indexer, dashboard, certificate generator, Python worker and optional Ollama) and validate provenance/signatures according to your registry trust policy. The repository does **not** currently enforce digest pinning.
- Model blobs and licenses require separate review. A model tag, a successful download or local inference does not establish model integrity or accuracy.

## Actual image vulnerability review (scheduled, no deployment)

[Container vulnerability scan](../.github/workflows/container-vulnerability-scan.yml) checks the three Wazuh images, certificate generator, local Ollama and Python worker weekly or on manual dispatch. It uses SHA-pinned Trivy action `ed142fd0673e97e23eac54620cfb913e5ce36c25` (release v0.36.0) and **fails** on HIGH/CRITICAL fixable vulnerabilities. Findings require security-owner triage, actionable remediation or a time-limited exception, not a silent workflow bypass. The scan has no Docker or GitHub write permissions and cannot promote an image.

**Caveat:** These are still *tagged* images. This action does not authenticate a publisher, verify signatures, generate a full SBOM, or lock immutable multi-platform manifest digests. Verify each registry digest on the deployment architecture using `docker buildx imagetools inspect IMAGE:TAG`, then perform a reviewed PR pinning tag+digest and retaining provenance evidence. No digest should be invented or assumed from an abbreviated Docker Hub display. A signed-off registry and CVE policy remain required for enterprise deployment.

## Continuous maintenance

The scheduled [upstream release monitor](../.github/workflows/upstream-release-watch.yml) compares the official Wazuh Docker *latest stable release* with the repository's declared release version. It reports drift; it **does not modify** image tags, generate changes, start containers or install pre-releases. This is advisory monitoring, **not** vulnerability scanning.

Run periodic container and Python dependency vulnerability scanning with your approved tooling; link findings to an accountable owner, severity, expiry and patch window. Apply environment-specific signatures and SBOM retention. Scan the host, Docker daemon and runtime config as separate assets. Keep a repeatable rollback artifact of the exact previous images, config and snapshots.

## Change gates

A version or image digest PR must include: vendor release note evidence, compatibility matrix, per-platform digests, scan/SBOM reports, TLS and Indexer compatibility, clean install results, staged migration and rollback, impact to agent versions, and a signed change approval. The main CI tests static contracts only. Production promotion requires the independent [acceptance protocol](PRODUCTION_ACCEPTANCE.md).
