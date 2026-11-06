# Backup, retention and restoration: self-hosted Wazuh

**Status: backup automation partially implemented; operational prerequisites still required.** The opt-in `scripts/snapshot_guard.py` and `docker-compose.backup.yml` support bounded alert snapshot creation/status verification against an *existing* approved repository, but do **not** configure the repository, provide off-host transport, encrypt storage, schedule backups by default, back up manager state, or demonstrate restoration. Docker named volumes are persistence, **not** an independent backup. A successful source-code CI check is not a restore test.

## 1. Define the recovery contract

Before enabling production telemetry, document the business-approved **RPO** (maximum acceptable data loss), **RTO** (time to restore an usable service), retention and deletion periods, legal restrictions, backup owner, recovery owner and independent restore approver. Use an encrypted off-host or off-site storage destination with service credentials scoped to snapshot operations and auditable access. Store recovery keys separately from the data they protect.

## 2. What must be captured

| Asset | Source in this repository | Recovery considerations |
| --- | --- | --- |
| Indexed alerts, search metadata and dashboards | `wazuh-indexer-data` | Use **supported OpenSearch/Wazuh Indexer snapshots**; never treat a live data-directory copy as a reliable snapshot. Preserve compatible index/cluster version metadata. |
| Manager settings, agent identities, keys, queues, custom rules and active-response files | `wazuh_etc`, `wazuh_api_configuration`, `wazuh_queue`, `wazuh_logs`, `wazuh_integrations`, other `wazuh_*` volumes | Coordinate a quiesced/consistent copy with an approved recovery window and document which transient queue data can be lost. |
| Filebeat state | `filebeat_etc`, `filebeat_var` | Restore only with a compatible manager/Filebeat configuration; avoid replay or skip surprises. |
| Dashboard customizations | `wazuh-dashboard-config`, `wazuh-dashboard-custom` | May contain integration settings and sensitive objects; validate compatibility. |
| Credentials and PKI | `.env`, `config/generated/`, `config/wazuh_indexer_ssl_certs/`, host-side role/rotation records, persisted enrollment `authd.pass` | Sensitive: use owner-only access, encrypted backup and independent key escrow. **Bootstrap is not a running-cluster credential-rotation mechanism.** |
| Deployment definition | Git commit SHA, image **digests**, Compose rendered config hash, DNS/firewall rules | Do not publish a resolved Compose file: it can include passwords. Keep evidence in a restricted operator vault. |
| Opt-in AI state | `ai-ollama-data`, any local AI secrets and model provenance | Auxiliary; Wazuh recovery must not depend on Ollama. Retain only under approved data-handling policy. |

## 3. Opt-in snapshot execution and verification

The snapshot helper is **plan-only by default**; it cannot delete, register repositories or restore data. A dedicated backup operator (separate from Wazuh admin, permissions limited to the required snapshot actions) must be provisioned using the running Indexer security API. Verify the user has **no** index deletion, role modification, host-shell or Manager API permissions. Security-plugin snapshot operations require carefully scoped cluster permissions; do not reuse dashboard service or AI reader identities.

```bash
# Offline: no network, no credentials, no mutation.
python3 scripts/snapshot_guard.py --repository wazuh-offsite --mode plan

# Inside the private Docker bridge, after an operator configured an actual off-host
# Indexer repository named wazuh-offsite, created a dedicated snapshot user,
# installed its password into local-secrets/snapshot-indexer-password (0600),
# and confirmed the repository's remote durability and encryption.
docker compose -f docker-compose.yml -f docker-compose.backup.yml \
  run --rm --no-deps snapshot-guard --repository wazuh-offsite --mode create --apply \
  --ca-file /certs/root-ca.pem --username wazuh-backup \
  --password-file /run/secrets/snapshot-indexer-password

# Copy the generated snapshot name from the previous JSON output, then verify it:
docker compose -f docker-compose.yml -f docker-compose.backup.yml \
  run --rm --no-deps snapshot-guard --repository wazuh-offsite \
  --mode verify --snapshot wazuh-YYYYMMDDtHHMMSSz \
  --ca-file /certs/root-ca.pem --username wazuh-backup \
  --password-file /run/secrets/snapshot-indexer-password
```

The helper selects only `wazuh-alerts-4.x-*`, with `partial=false`, `include_global_state=false`, and strict failure checks. **It is not a complete Wazuh backup**, does not include security state, other Indexer indexes, manager data, certificates or credentials, and verification only establishes API-reported success. Check that the repository is **truly off-host** and encrypted, enforce retention separately, and perform an isolated restore before meeting the recovery gate. For periodic automation, deploy an approved host timer that runs the one-shot Compose command and separately verifies each snapshot, detects stale backups, and alerts on non-success exit codes. Avoid committing operator credentials or emitting passwords to command arguments.

## 4. Configure Indexer snapshots **outside this repository**

Use the [Wazuh Indexer migration/snapshot guidance](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/migrating-wazuh-indices.html) and the version-compatible [OpenSearch snapshot/restore documentation](https://docs.opensearch.org/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/). A snapshot repository requires an **explicitly configured, approved destination**: for example, a dedicated filesystem mount plus an appropriate `path.repo` setting, or a compatible object-storage repository plugin. This Compose file supplies neither one. Do not assume `/_snapshot/...` works until the repository is configured and verified on your deployment.

Using an approved, authenticated administrative client on a trusted private network, the **API procedure** is:

```http
GET /_snapshot/_all
POST /_snapshot/APPROVED_REPOSITORY/_verify
PUT /_snapshot/APPROVED_REPOSITORY/test-YYYYMMDDTHHMMSSZ?wait_for_completion=true
Content-Type: application/json

{"indices":"wazuh-alerts-*,wazuh-monitoring-*","include_global_state":false,"ignore_unavailable":true,"partial":false}
GET /_snapshot/APPROVED_REPOSITORY/test-YYYYMMDDTHHMMSSZ/_status
```

The `APPROVED_REPOSITORY` and snapshot name are **placeholders**, not configured by this project. Adjust the exact index selection based on your deployed Wazuh version and approved retention/classification requirements. In particular, **do not silently back up or overwrite the OpenSearch Security index**: plan security/RBAC recovery separately. Capture completion state, snapshot UUID, backing storage encryption, retention, index counts and the backup operator in a private evidence store.

**Security:** the indexer is intentionally **not** published to the host. Do not expose port 9200 publicly for backup convenience or bypass certificate checking with `curl -k`; connect using a short-lived, approved client with TLS and the minimal privileges required by the operations performed. Avoid copying private key paths or auth headers into tickets.

## 5. Rehearse an isolated restoration

1. Build an isolated target with the **approved version-compatible** Indexer binaries and distinct host storage/network. Verify the destination has capacity for all restored shards and that the backup repository is mounted **read-only** on the restore target.
2. Restore required manager/agent identity materials, configuration, certificates and dependent credentials under change control. Confirm secrets ownership/modes and that no agent will accidentally connect to production.
3. Register the approved snapshot repository as read-only; select the exact snapshot and explicitly review excluded system/security indices, index naming conflicts and cluster settings. Restore **only** into this isolated cluster using the vendor-supported API/UI procedure.
4. Compare source and restored index lists/counts and sampled alert identifiers; test manager API, dashboard authentication, Wazuh rule processing, test agent heartbeat, alert ingestion and searches. Verify the approved user/role mapping; **never inherit unsafe security state without review**.
5. Measure actual time-to-recovery and data-loss window against documented RTO/RPO. Rotate or invalidate any exposed credentials and isolate the recovered environment after evidence collection.
6. Store the test result in your restricted evidence system. Record failures, responsible owner, mitigation deadline and next scheduled rehearsal.

**Rollback caution:** an older Indexer may not read indices written by a newer major version. Restoring into older software is not a safe alternative to a vendor-supported migration plan. Test and retain a matching pre-upgrade snapshot before every release migration.

## 6. Incident response and retention

On ransomware, disk corruption, suspected credential compromise or an unexpected loss of Indexer availability: preserve forensic evidence, stop new enrollment if necessary, verify snapshot repository integrity independently, recover in an isolated target, and document any lost alert interval. Never delete snapshot files manually: incremental snapshots share data; use the supported snapshot retention/deletion API with approvals.

Read alongside [operations](OPERATIONS.md), [staging acceptance](PRODUCTION_ACCEPTANCE.md) and [release upgrades](UPGRADING.md).
