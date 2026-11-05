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
