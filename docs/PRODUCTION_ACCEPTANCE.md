# Staging validation and production acceptance protocol

This is a **manual evidence-based gate**, not a promise that CI runs Wazuh containers. Run on a fenced staging environment built from the exact approved image digests and deployment configuration. Never use a real production agent or copy sensitive production evidence into GitHub Actions.

## Acceptance record

Record outside this repository: commit SHA, official Wazuh release, image digests and source attestations, Docker/kernel versions, configuration hash, host/network topology, test operator, UTC timestamps, expected RPO/RTO, test results, evidence location and two independent sign-offs.

| Gate | Operator procedure | Pass criterion |
| --- | --- | --- |
| Version and provenance | Compare all manager/indexer/dashboard image digests and configs with an approved upstream stable release; run organization vulnerability scanner | No unresolved *unaccepted* critical findings, digests recorded; no pre-releases or tag-only trust |
| Secure ingress | Probe dashboard, agent enrollment/transport, manager API and indexer API from permitted/denied VLANs; inspect published ports | Only explicitly approved sources can connect; indexer is not publicly published; enrollment protected |
| TLS and access | Verify CA chain, SAN, expiry, server hostname and rotation drill; log in with restricted user; test denied roles | No insecure TLS bypass; denied non-alert index reads and all unauthorized writes; credentials absent from logs |
| Startup and ingestion | Start services; enroll test Windows and Linux agents in staging; trigger synthetic alerts; search via Indexer and dashboard | Real alerts arrive within agreed latency, with correct timestamps and rule metadata |
| Index capacity | Apply representative ingestion and search workloads; monitor heap, disk, shards and CPU | Approved sizing headroom and alerting at configured disk/high-water thresholds; no full-disk surprise |
| Recoverability | Use documented Indexer snapshot API and back up manager state, agent keys, TLS and configuration; restore into an isolated host/cluster | Data/agent identities restored consistently within approved RPO/RTO, with reconciled index counts |
| Fault tolerance | In a **multi-node** stage only, interrupt manager, indexer node, ingress proxy and an entire host one at a time | Measured failover meets SLO, indexing and search recover, no unplanned duplicate agent enrollment |
| Backup security | Inspect destination ACLs, encryption, offsite copy, retention, deletion and recovery access | Scoped access, recovery keys independently stored, alerts on stale/missing snapshots |
| Observability | Validate monitoring for disk > capacity policy, JVM, indexing lag, dropped events, disconnected agents, cert expiry and Wazuh API failures | Every critical alert is routed to a named on-call owner; exercises produce actionable events |
| AI isolation | Run adversarial fixtures with local Ollama on separate hardware; test denied model/worker egress and Indexer reader permissions | No model-driven actions, raw-alert leakage or unauthorized network path; measured analyst accuracy and rollback |
| Change/rollback | Stage upgrade and rollback using independent snapshots; exercise stop/start, incident and change approvals | Bounded, rehearsed and documented cutover, with confirmed restored state after rollback |

## Practical commands and negative checks

Run in the **approved staging environment** only:

```bash
python3 scripts/enterprise_preflight.py --profile controlled --host
python3 scripts/bootstrap.py --check
docker compose -f docker-compose.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.ai.yml config --quiet
docker compose ps
docker compose logs --tail=100 wazuh.manager wazuh.indexer wazuh.dashboard
```

Check binding using `docker compose ps` and the host firewall. **Do not paste `docker compose config` without `--quiet` into tickets**: resolving environment variables can reveal credentials. Verify certificates using approved `openssl x509 -noout -dates -ext subjectAltName -in <public-cert-file>` commands; never print or upload private keys.

For authenticated Indexer tests, use a dedicated staging-only reader principal and your approved secret-handling method. Validate successful bounded `_search` on `wazuh-alerts-4.x-*`, and **denials** for other indices, security administration and writes. Do not test mutating API calls on production. Confirm a wrong-CA connection fails rather than disabling verification.

## Non-goals and failure handling

- `docker compose config --quiet` verifies a configuration model, **not** successful image startup, CVE safety, agent enrollment or recovery.
- Docker named volumes are **not backups**; snapshot and offline copy must be tested independently.
- Loss of the one Docker host is an **expected outage** for the bundled single-node stack. Do not mark HA as passed there.
- A passing offline AI fixture is **not** a validation of actual threat-detection quality.

Any P0/P1 security, integrity, access-control or restore failure blocks deployment promotion. Record explicit exception owner/expiry when allowed by organizational policy; never silently treat an untested case as passed. Re-run the affected gates after changing Wazuh versions, certificates, network design, the underlying host or LLM artifacts.

See [enterprise readiness](ENTERPRISE_READINESS.md), [operations](OPERATIONS.md), [upgrade runbook](UPGRADING.md) and [AI validation](AI_VALIDATION.md).
