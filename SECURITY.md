# Security policy

## Supported deployment

This repository publishes a version-aligned Wazuh single-node Compose configuration. The image tags are pinned to the supported upstream **4.14.9** stable release as of November 2026. The project is not a managed security service and makes no claim that configuration-only CI equals production certification.

## Default safeguards

- Generates unique passwords for indexer admin, dashboard service and manager API integration; no known sample passwords are committed.
- Enables certificate-backed TLS among components, based on Wazuh's official certificate generator and matching config files.
- Binds host-facing dashboard, agent and manager API endpoints to loopback by default, and does not publish the indexer API.
- Avoids Docker daemon socket mounts, host PID namespace, unnecessary capabilities and hard-coded public-range IPv4 addresses.
- Keeps runtime secrets, generated configs and TLS private keys out of Git using `.gitignore`; validates these boundaries in CI.
- Applies read-only bind mounts for trusted configuration and certificates where practical, and keeps long-lived application state in named volumes.

## Security responsibilities

Docker host administrators can access environment variables and container state; current v4.14.9 Wazuh images use environment variables for service credentials. The private `.env` is therefore **not equivalent to a hardware-backed secret store**. Keep host access limited, protect backups, use trusted certificates for remote users, and restrict who can connect to enrollment and APIs. For remote agent traffic, use explicit firewall/VPN rules and review enrollment authentication.

The initial password generator only provisions an **empty** security database. A live indexer's credentials cannot be rotated safely by rerunning the generator. Password changes must follow supported Wazuh/OpenSearch procedures and update all dependent services. Avoid uploading `.env`, private PEM files, index snapshots or incident artifacts to public tickets.

No HA, snapshot schedule, automated recovery, external SIEM policy or network firewall is configured for you. Review [Operations](docs/OPERATIONS.md) and [Upgrading](docs/UPGRADING.md) before a production change.

## Reporting a vulnerability

Do **not** post credentials, exploit details, or private security logs in public issues. Use GitHub private vulnerability reporting when enabled, or contact the repository maintainer through a trusted private channel. For vulnerabilities in Wazuh binaries or images, use the vendor's published security reporting process. Include affected component versions and a sanitized reproduction.

## Optional AI integrations

AI inference is **disabled in the default stack**. The separate [AI threat model](docs/AI_SECURITY.md) documents the read-only Indexer principal, bounded search, local model allowlist, data minimization, prompt-injection defenses and human-approval requirements. AI output is not evidence and must never authorize automated Wazuh actions. Review [AI HOWTO](docs/AI_HOWTO.md) and [validation](docs/AI_VALIDATION.md) before connecting a live environment. Do not use Wazuh `admin` credentials, unverified remote MCP gateways or the Manager API for the sample worker.

## Deployment authorization and enrollment

The current manager template requires password-authenticated enrollment (`<use_password>yes</use_password>`), while existing running deployments require explicit staged conversion and container-level verification. **Do not broaden TCP 1515 exposure** until the private enrollment secret is mounted successfully, denied unauthenticated enrollment has been demonstrated, and host firewall/source restrictions are approved. Loopback defaults are not a full ingress policy.

The upstream-based Indexer configuration disables OpenSearch disk-allocation thresholds. Full disks can impact ingestion and integrity; evaluate a Wazuh-version-compatible disk watermark policy, proactive disk alarms and tested recovery **in staging** before changing a live cluster. See the [enterprise readiness standard](docs/ENTERPRISE_READINESS.md) and [staging acceptance](docs/PRODUCTION_ACCEPTANCE.md).

CI now includes a read-only static policy check; it does **not** start containers, scan image CVEs, enforce branch protection or verify any real deployment. GitHub repository administrators must separately enable branch protection, code owner reviews, secret scanning and supply-chain policies.

## Enrollment, recovery, and image integrity controls

New installations now require an agent enrollment password; Wazuh 4.x agent operators must receive the secret through an approved channel. Existing deployments are **not** silently converted: use the idempotent `scripts/enrollment_security.py` conversion in staging, verify read-only bind permissions in the container, and close 1515 ingress if negative enrollment tests fail. See [agent enrollment](docs/AGENT_ENROLLMENT.md).

The Indexer config now includes explicit single-data-node disk watermarks, whose actual flood-stage response must be rehearsed. The optional snapshot helper does not delete or restore data, and is not a replacement for encrypted off-host full-system recovery. A scheduled SHA-pinned vulnerability scan discovers container issues but does not certify image origin or enforce immutable digests. These are independent operator-owned controls, not a production approval.
