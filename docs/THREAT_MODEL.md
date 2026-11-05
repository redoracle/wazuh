# Security threat model: historical Wazuh Docker deployment

> **Model status:** static configuration analysis only. This model does not
> validate actual vendor image behavior, certificates, firewall policies,
> running secrets or the safety of a deployed environment.

## Assets and trust boundaries

| Asset / boundary | Exposure in historical configuration | Mitigation / validation required |
| --- | --- | --- |
| Docker host and daemon | Filebeat/Metricbeat mount the daemon socket; several collectors use root and capabilities | Isolate and deny access to untrusted users; remove sockets in a new design |
| Host OS logs/processes | Auditbeat uses host PID and audit capabilities; journal/metric collectors read host state | Dedicated audited hosts, least-privilege collectors and data minimization |
| Wazuh credentials | Nginx reads environment variable, format and storage unverified | Secret manager, limited access, rotation, logging redaction, TLS in replacement stack |
| Event indices and rules | Elasticsearch/Kibana storage paths may be incorrect | Verify actual data paths and restore; use new indexer and supported migration |
| `sll_net` and agent traffic | External shared network with globally routable `172.13.x.x` addresses | Private IP plan, firewalls, TLS, controlled network membership |
| GitHub CI / maintainer credentials | PRs can change workflows, docs and baseline tests | SHA-pinned actions, read-only token, branch rules, independent PR review |

## Abuse cases and controls

1. **Host takeover via Docker socket:** a `:ro` bind mount only limits
   filesystem writes, not API requests over the socket. Treat access as
   host-administrative. Gate any new socket mounts with static/JSON tests;
   architect them out in the supported target environment.
2. **Privilege escalation via Compose edit:** adding `privileged`, host PID,
   Linux capabilities, devices, a new bind mount, another network or host
   published port may increase exposure. The resolved-model validator fails
   closed against the audited baseline. A maintainer can deliberately update
   that baseline only with security review and runtime evidence.
3. **Credential leakage:** avoid publishing `docker compose config` JSON,
   container environment variables, real `.env` contents or raw `docker
   inspect` dumps. CI runs a synthetic non-secret value and validates JSON via
   a pipe; the validator prints only safe generic reasons.
4. **Data loss during image upgrade:** changed index formats or incorrect
   persistence assumptions can corrupt/unrecoverably lose historical events.
   A verified snapshot, staged migration and restore drill are mandatory.
5. **Supply-chain compromise:** test-only Python packages and GitHub Actions
   are version/SHA pinned and reviewed via Dependabot. Obsolete container
   binaries remain an acknowledged open risk until replacement.

## Security acceptance criteria

A modern deployment may not be called secure until privileged host access has
been explicitly minimized or justified, transport/authentication and
certificate lifecycle are tested, images are supported and scanned, data
persistence and restoration are demonstrated, and private networking and
access controls are verified under real workloads. Static CI **cannot**
validate those outcomes.

See [security policy](../SECURITY.md),
[second audit](SECOND_AUDIT.md) and [migration plan](UPGRADE.md).
