# Enterprise self-hosted architecture and readiness standard

**Status: NOT APPROVED FOR HIGH-AVAILABILITY PRODUCTION.** This repository currently ships one Wazuh 4.14.9 manager, one indexer, and one dashboard on a single Docker host. It is a useful reference for controlled self-hosted deployments, **not** an enterprise HA architecture. Running CI or the optional AI worker does not change this status.

## Reference architectures and decision

| Capability | This repository: controlled single host | Required for an HA deployment |
| --- | --- | --- |
| Manager | One container; no failover | Upstream-supported master/worker manager cluster and tested manager ingress/load balancing |
| Indexer | One node and one persistent volume | Vendor-supported three-node indexer cluster, failure-domain placement, shard/replica plan and tested quorum recovery |
| Dashboard | One instance | Defined availability target, supported redundancy/restore strategy, trusted ingress |
| Network | Compose bridge and loopback port defaults | Approved network segmentation, ingress allowlists, host firewall, denied unauthorized egress, audited access |
| Credentials | Local bootstrap, protected `.env`, runtime environment variables | Central lifecycle, restricted Docker host access, tested rotations, RBAC and audit records |
| Backups | Guidance, no scheduled job or proof | Consistent, encrypted **off-host** Indexer snapshots plus manager, credentials, certs; rehearsed restore |
| Availability | Docker `restart: unless-stopped` only | Multi-host failure testing, operational SLOs, capacity planning, alerting and on-call ownership |
| Change control | Pinned workflow actions and test gates | Protected default branch, 2-person review, release pin/digest attestation, deployment approval and rollback |
| AI | Read-only optional triage with human sign-off | Dedicated reader/FLS, measured model accuracy, hard egress policies and separate inference capacity |

**Preferred HA design:** Start from Wazuh's *official multi-node Docker* release bundle, not by cloning services from this single-node Compose file. The official template includes three indexers, two managers, a dashboard and load balancing; a single Docker host still constitutes one failure domain. Deploy to independently resilient hosts or an approved orchestrator with persistence and network guarantees that match your RPO/RTO.

Vendor references: [Wazuh Docker installation and single/multi-node architectures](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html) · [Wazuh Docker v4.14.9 upstream release](https://github.com/wazuh/wazuh-docker/releases/tag/v4.14.9) · [Indexer sizing](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html).

## Ranked findings (2026-11-06)

| Priority | Finding and evidence | Required mitigation |
| --- | --- | --- |
| **P0** | No high availability: `discovery.type: single-node`, one manager, one indexer, one dashboard | Vendor-aligned multi-node migration; staging loss-of-host, loss-of-indexer and failover tests |
| **P0** | No automated, demonstrated Indexer snapshot/restore or durable off-host storage workflow | Approve snapshot repository, independent backup encryption, restoration rehearsal and measurable RPO/RTO |
| **P1** | Manager template sets `<use_password>no</use_password>` for agent enrollment; publishing `1515` may widen the enrollment attack surface | Keep agent ports bound to loopback until ingress/firewall and supported authentication procedures are approved; stage-test enrollment |
| **P1** | Indexer sets `cluster.routing.allocation.disk.threshold_enabled: false` in the upstream-based config | Validate the 4.14.9-compatible disk watermarks, headroom and low-disk response with the indexer vendor; do not blindly flip the setting on a live node |
| **P1** | Image tags, including the AI worker's `python:3.13-slim`, are mutable and there is no image scanning/signature policy | Review images, lock approved platform digests, collect SBOM/provenance and establish actionable CVE gating |
| **P1** | Default GitHub `master` is currently not branch-protected; repository files alone cannot enforce reviews | Enable branch protection/rulesets, required status checks, independent approvals, and secret/push protection |
| **P1** | No deployed telemetry thresholds, SLO/error budget, scheduled restoration or operational sign-off | Set indexer disk/JVM, ingest lag, agent heartbeat, TLS expiry, snapshot age and security anomaly alerts |
| **P2** | Docker stdout/stderr logging was unbounded; a busy or broken service can fill the host filesystem | Added per-service `json-file` rotation, 10 MiB × 5 files per container; configure durable off-host audit-log retention separately |
| **P2** | AI model network is a Docker bridge, **not** an enforced air gap; Docker host administrators can inspect mounted secrets | Apply network egress controls outside Compose, isolate model hardware, enforce reader role and operational validation |
| **P2** | CI is offline/static; it does not validate real Wazuh startup, enrollment, upgrades or certificate renewal | Perform the [production acceptance suite](PRODUCTION_ACCEPTANCE.md) in dedicated staging and retain signed evidence |

**Do not claim “enterprise-ready”** merely because the `controlled` static policy passes. The `enterprise` policy deliberately fails while architectural and operator-owned gates remain unmet.

## Operational procedures and evidence

The following runbooks document **operator-owned controls**, not auto-installed enterprise services: [secure agent enrollment](AGENT_ENROLLMENT.md), [encrypted off-host backup and isolated recovery](BACKUP_RESTORE.md), and [certificate trust, expiry and rotation](CERTIFICATE_OPERATIONS.md). Record completion and failed negative tests outside Git. Use `make docs-check` for offline documentation validation and `make cert-check` for host-side OpenSSL verification after generating certificates. The host preflight also checks whether generated configuration directories and private TLS keys are exposed to other users.

## Non-destructive preflight

Install development tooling (`python -m pip install -r requirements-dev.txt`), then run:

```bash
make preflight   # static repository contract: pass/warn/block
python3 scripts/enterprise_preflight.py --profile controlled --host
python3 scripts/enterprise_preflight.py --profile enterprise --json
```

The enterprise command is **expected to return a nonzero exit code** and report unresolved blockers. Its JSON contains no credential contents. `--host` inspects `.env` mode, referenced TLS certificate presence and host bind address scope; it is not a certificate-expiry scan, a container runtime audit, or permission to deploy. If operator data are missing, this is a *blocker*, not a green badge.

## Promotion and ownership policy

1. Record business owner, security owner, change approver, workload criticality, asset inventory, data classification and retention obligations.
2. Select required service levels: maximum event-loss budget (RPO), recovery time (RTO), target availability, ingress zones and supported agent population. Benchmark actual alerts/sec, shards, storage and sustained query latency on production-like data.
3. Build the vendor-supported multi-node alternative in isolated infrastructure; enforce ingress/egress at the host and network layer, not only Compose labels.
4. Add encrypted, verified off-host backups; restore snapshots *and* agent keys, TLS and manager configuration into an isolated environment with all secrets rotated as required.
5. Execute [acceptance protocol](PRODUCTION_ACCEPTANCE.md), including negative permission testing and loss-of-host drills, and obtain two-person approval. Store evidence outside Git.
6. Only then label the specific **deployment** production-approved. Keep source-level CI, runtime monitoring and restore tests continuously active.

The optional Ollama triage remains advisory and must never be a prerequisite for Wazuh ingestion, alert storage or response. See [AI security boundaries](AI_SECURITY.md).
