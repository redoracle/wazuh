# Operations runbook

## Routine inspection

Use `docker compose ps`, `docker compose logs --tail=200 <service>` and `docker stats` to inspect availability and resource pressure. Monitor indexed event throughput, agent connectivity, manager alerts, disk watermarks, JVM pressure, certificate expiry and security log anomalies.

`make status` and `make logs` are short forms. Avoid printing `.env` or resolved Compose environment into untrusted CI logs or support tickets.

## Persistence and backups

The indexer volume `wazuh-indexer-data` contains search data; the manager has separate `wazuh_*` named volumes and Filebeat state volumes. Host-side artifacts include `.env`, `config/generated/` and `config/wazuh_indexer_ssl_certs/`. Record the exact service version and image digests with your backup.

For **consistent indexer backups**, use the Wazuh/OpenSearch-compatible snapshot method supported by the deployed indexer version; merely copying the live data directory can produce an unrecoverable snapshot. Back up manager configuration/rules, agent identity and keys, dashboards/customizations, and TLS/credential materials using a documented consistency window.

Test a restore into a segregated environment **before** relying on the backup. Confirm agent enrollment, indexing, dashboard authentication and searches. Store backups encrypted, off-host, with restricted recovery access and retention controls.

## Restart and stop

```bash
docker compose restart wazuh.manager
docker compose ps
docker compose down  # preserves named volumes
```

**Never use `docker compose down -v` as a routine command.** It deletes the stored service state. Do not reset passwords by recreating indexer volumes. Restarting is not an upgrade method.

## Incidents

1. Contain exposure by restricting published host ports and suspicious client sources; preserve logs and a read-only state copy when possible.
2. Record current image digests, component versions, active processes, container inspection artifacts, network policy and timestamps. Avoid leaking secrets in collected diagnostics.
3. Rotate affected credentials using vendor-supported procedures and update consumers; do not overwrite the bootstrap-generated files independently of the running security index.
4. Restore verified backups and certificates if integrity or availability cannot be recovered safely. Keep recovery environments isolated until acceptance checks succeed.
5. Document root cause, detection gaps, durable remediation and recurrence prevention.

## Monitoring and scale

The configuration is a single-node platform; it has no index replica or dashboard failover. For increasing ingestion volume, explicit availability targets, compliance evidence or fault tolerance, plan an upstream-supported multi-node topology and retention strategy. See [Upgrading](UPGRADING.md).
