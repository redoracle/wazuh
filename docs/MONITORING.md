# Enterprise monitoring and incident escalation acceptance

**Not automatically deployed.** [Prometheus reference rules](../monitoring/prometheus-rules.example.yml) provide host disk and core-service health examples. They will **not work** unless the operator deploys and secures exporters, sets matching `job`/`mountpoint` labels, verifies alert routing, and confirms Prometheus actually evaluates the rules. The repository does not publish manager API/Indexer host ports to accommodate monitoring.

## Required signals and independent alerting

| Signal | Suggested initial trigger | Evidence to retain |
| --- | --- | --- |
| Indexer host disk | Warning below 25% free, critical below 15% free; tune to workloads | Host disk/inode metrics, page delivery, full-disk simulation response |
| Indexer cluster state | Red, long-lived yellow, missing node, shard placement errors | TLS-authenticated health history and shard metrics |
| Indexer JVM and query pressure | Sustained heap or latency limit from capacity benchmark | JVM/memory graphs, p95 query and ingest lag by host |
| Agent heartbeat and ingestion | Missing expected endpoint heartbeat or alert age beyond business SLO | Synthetic test agent + known event indexed and searched |
| Manager/API dashboard availability | Failed black-box authenticated check | Probe error, on-call acknowledgment, recovery record |
| Certificates | Alert at 45 days, escalate at 30 days | Private inventory of expiry and successful rotation rehearsal |
| Backup freshness | No **verified** snapshot within approved RPO; missing off-host copy | Snapshot UUID, remote storage encryption/durability and restore evidence |
| Security anomalies | Enrollment failures, role modifications, failed auth, unexpected network egress | Investigation ticket and independently retained logs |

Use a dedicated monitoring identity with least privilege and CA-verified HTTPS. Do not export `.env`, bearer tokens, credentials, or raw alert bodies into metrics labels or Grafana dashboards. For distributed deployments, record job labels and per-host failure domains so losing one exporter does not appear as a healthy empty metric set.

## Operator acceptance

1. Deploy independent monitoring outside the single Wazuh Docker host; exporters must fail closed on authentication and use pinned/signed images or approved packages.
2. Apply only the rule expressions appropriate for real exporter job/mountpoint labels. Use a Prometheus rule validator (`promtool check rules monitoring/prometheus-rules.example.yml`) and a controlled alert simulation before enabling production paging.
3. Simulate a single Indexer outage, manager outage, disk warning, expired certificate and stale snapshot *in staging*. Verify that alert delivery remains available even if the whole Wazuh host is lost.
4. Record escalation channels, rotation schedule, runbook URLs, incident responder and alert receipt evidence. Treat false-negative or missing-target alarms as release blockers.

These checks are operational acceptance requirements, not evidence that monitoring is already running. See [production acceptance](PRODUCTION_ACCEPTANCE.md) and [disk recovery](DISK_OPERATIONS.md).
