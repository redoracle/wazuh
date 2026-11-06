# Indexer disk protection, capacity and flood-stage recovery

**New configuration behavior:** the single-node Indexer file now explicitly enables `cluster.routing.allocation.disk.threshold_enabled` and `cluster.routing.allocation.disk.watermark.enable_for_single_data_node`, with low/high/flood-stage watermarks of 85%, 90%, and 95%. These are derived from [OpenSearch disk allocation settings](https://docs.opensearch.org/latest/install-and-configure/configuring-opensearch/cluster-settings/); the second setting matters because default behavior for a single data node can bypass disk checks. **No existing container is changed until its configuration is deployed/recreated.**

## Safe rollout

1. In an isolated Wazuh 4.14.9 staging environment with a **verified off-host snapshot**, inspect actual storage free space, inode pressure, shard distribution, alert ingestion and current active Indexer cluster settings. Choose capacity alerts well below 85% so an operator acts before high watermarks.
2. Verify settings accepted by the deployed Wazuh Indexer image. Run `python3 scripts/enterprise_preflight.py --profile controlled` and `docker compose config --quiet` before changing runtime. Do **not** assume source YAML means the running OpenSearch cluster accepted settings: persisted cluster settings may override configuration.
3. Roll out with an approved maintenance/recreation plan and record active effective values with a CA-validated, authenticated `_cluster/settings?include_defaults=true` request. Never disable TLS verification or paste admin credentials in commands or tickets.
4. Simulate disk-pressure thresholds in a disposable staging host with bounded test data and a restorable backup. Confirm that flood-stage protection prevents further index writes and raises monitoring alerts. **Do not** deliberately fill a production disk, create unsafe files, or delete system indexes to clear the block.
5. Increase allocated capacity or retire data using vendor-supported retention/index management. Once safe headroom is restored, verify index blocks recover, new events ingest, searches work, and alert gaps are accounted for. A disk-based write block can create real telemetry loss; treat it as an incident.
6. Capture threshold trip, observation timestamps, duration and recovery evidence. Set a separate host-level disk metric and alerting system (not merely Wazuh itself) so an exhausted Indexer still pages the on-call operator.

## Operating policy

- Alert at or below 70% utilization; maintain a documented buffer for restore, index merges and traffic surges.
- Monitor disk usage, inode availability, JVM pressure, shards, replicas, cluster status, Indexer queue and event ingestion age.
- Snapshot before changes, keep off-host copies and test restoring relevant indexes.
- Never use `cluster.routing.allocation.disk.threshold_enabled: false` as routine recovery. Any exceptional change requires a documented incident decision, a backup and an expiry.

**Acceptance remains open:** actual 4.14.9 Indexer boot, effective settings, flood-stage behavior, alert ingestion and recovery were not tested in this repository CI.
