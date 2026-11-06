# High-availability transition: pinned upstream Wazuh and independent failure domains

**Status: architecture design and acceptance gate, not a deployed HA stack.** The default `docker-compose.yml` intentionally remains a controlled single-host Wazuh v4.14.9 deployment. This guide is for a **separate new environment** and must not be run against existing named volumes. GitHub CI cannot prove host isolation, data movement, quorum or failover.

## 1. Establish a supported reference

The exact official Docker reference is [Wazuh Docker v4.14.9](https://github.com/wazuh/wazuh-docker/tree/v4.14.9/multi-node), commit `56ece955b1107b7b62823afae5b7057e1dab9d98`. The upstream example includes three indexers, one manager master, one manager worker, one dashboard, and Nginx ingress. All components in one Docker Compose project on **one host remain one failure domain**—this is not disaster-resilient infrastructure. Do not copy upstream sample credentials, public Indexer port, unauthenticated enrollment, or broad network exposure into production. Build your design using supported Wazuh clustering and the current official deployment guides.

```bash
# Run on a clean engineering workstation; do not use the running Wazuh data host.
git clone --filter=blob:none --branch v4.14.9 https://github.com/wazuh/wazuh-docker.git vendor-wazuh-docker
cd vendor-wazuh-docker
# Must exactly match the pinned commit; stop if mismatched.
test "$(git rev-parse HEAD)" = 56ece955b1107b7b62823afae5b7057e1dab9d98
# Inspect (never deploy unchanged): multi-node/docker-compose.yml and config/
```

Review the effective **version-matched** manager cluster, TLS certificates, Indexer cluster bootstrap, transport encryption, authenticated agent enrollment, dashboard credentials and security-role initialization. Any major version change requires a separate signed change request, index compatibility and migration testing. The example upstream Compose does not automatically distribute containers across independently managed hosts.

## 2. Multi-host placement contract

An illustrative topology file is [inventory.example.json](../deployments/ha/inventory.example.json). It is syntactically valid but uses `.example.invalid` hostnames and **cannot be deployed as-is**. Replace it with a private environment-specific inventory, reviewed firewall/secret/network plans and a supported orchestrator. Check its *design* with:

```bash
python3 scripts/validate_ha_inventory.py --inventory deployments/ha/inventory.example.json
```

This checker requires three Indexers on three distinct hosts/failure domains, at least two managers, two dashboard instances and complete ingress backend inventories. It rejects reused hosts and service identities. **It does not create containers**, verify that DNS points to distinct failure domains, enforce egress, test HA election, or approve deployment. Availability targets and dashboard-redundancy support must be confirmed for the chosen Wazuh 4.x release. A master/worker Wazuh manager configuration is **not** an unconditional automatic-master-failover promise.

| Traffic | Minimum handling | Source restriction |
| --- | --- | --- |
| Agent telemetry | TLS/TCP 1514 through approved load balancer | Agents/VPN CIDRs |
| Agent enrollment | TCP 1515, Wazuh 4.x shared password and certificate/identity controls | Enrollment subnet only |
| Manager cluster | TCP 1516 among managers | Manager members only |
| Indexer API | HTTPS 9200 to authorized central components/backup operator | No public host port |
| Indexer transport | TLS 9300 among Indexer nodes | Indexer nodes only |
| Manager API | HTTPS 55000 for dashboard and approved administrators | Restricted admin plane |
| Dashboard | HTTPS 443 through trusted ingress | Approved operator networks |

Require encrypted, routable node-to-node networks with real service certificates whose SANs match DNS/IPs; the Docker bridge from this repository does not extend safely across hosts. Secure administrator/CI provisioning through a secrets manager. Do not mount Docker socket or reuse service `admin` for application integrations.

## 3. Safe migration sequence

1. Approve inventory, availability budget, E2E ownership and target Wazuh support matrix. Collect image digests and high/critical vulnerability review.
2. Provision clean hosts in separate failure domains with dedicated encrypted data storage, network policy, DNS, load balancers, secret backend and alerting. Keep all public indexer and manager API ports closed.
3. Install and validate a *separate* Wazuh multi-node release bundle and certificate set; use different Compose project names and secrets. Demonstrate TLS mutual trust, Indexer quorum, manager cluster synchronization, least-privileged user roles, denied unauthorized enrollment and complete alert search.
4. Create a verified **off-host** snapshot repository. Perform source snapshots and compatible target restoration with the version-specific [Wazuh index migration process](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/migrating-wazuh-indices.html). Restore manager keys and custom rules using a separate controlled consistency plan; do not mix incompatible volumes or blindly carry over security database indexes.
5. In staging, terminate one Indexer host and observe shard/replica behavior, alert visibility, write availability and cluster recovery; terminate the manager worker and master **separately**, documenting which services remain available and what manual recovery is needed. Fail over dashboard ingress and restore network partitions. Measure actual data loss and RTO against approved targets.
6. Exercise an off-host recovery of both Indexer alert data and manager/agent identity state; verify enrolled agents, fresh alerts, search and dashboard logins. Run [production acceptance](PRODUCTION_ACCEPTANCE.md) and obtain an independent two-person review before any cutover.
7. Run a staged cutover with a validated rollback route. **Never** call `docker compose down -v` against the source cluster or delete source backups during the observation window.

## Evidence required for closure

Attach a private signed deployment manifest, host failure-domain confirmation, Indexer cluster-state outputs (redacted), managed agent test results, TLS/security policy evidence, off-host snapshot UUID and restore drill results, RPO/RTO measurement, scan/SBOM provenance and explicit approval. The inventory checker returning `architecture_check_passed` is **only a design check**; its output always sets `enterprise_approval` to `NOT_GRANTED`.

Sources: [Wazuh Docker deployment](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html), [Wazuh architecture](https://documentation.wazuh.com/current/getting-started/architecture.html), [Indexer migration](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/migrating-wazuh-indices.html).
