# Operator runbook: non-destructive inspection and controlled recovery

> **Scope:** existing, *isolated* historical installations only. This is not a
> new-deployment guide. No commands below pull images, create services, or
> change production state. Verify every prerequisite independently. See
> [SECURITY.md](../SECURITY.md) and the [migration plan](UPGRADE.md).

## 1. Preflight / evidence collection

Run from the repository directory on the relevant host, **without pasting
credential values into issue reports or CI logs**:

```sh
# Structural validation only: no containers started, images pulled or networks created.
python -m pip install -r requirements-dev.txt
make check
# Runs offline tests plus both Compose model checks; no images pulled.

# Inspect the *existing* Docker network's IPAM, membership and routing.
docker network inspect sll_net

# Inventory existing services and their state; may show historical names.
docker compose -f docker-compose.yml ps --all
```

Confirm the expected ten services, **no published host ports by this file**,
network allocations, images and original image digests. Image tags are not
immutable; preserve the actual digests during backup and rollback planning.
Do not run `docker compose pull`, `up`, `down`, or `down -v` as an inspection step.

### Go / no-go conditions

| Gate | Required evidence before changing the environment |
| --- | --- |
| Network | `sll_net` IPAM and routes inspected; public-range conflict understood |
| Credentials | Secret storage, access and rotation procedure reviewed |
| Privilege | Socket mounts, root and Linux capabilities individually authorized |
| Persistence | Actual application storage paths mapped from **running** containers |
| Data safety | Consistent backup plus successful **isolated restore test** |
| Compatibility | Vendor-supported migration/version combination established |
| Observability | Known-good alerts, ingestion, search and dashboard baseline recorded |

**No-go** if any gate is missing. Do not treat static CI success as a runtime
security or recovery endorsement.

## 2. Verify live behavior without changing configuration

For an already running legacy system, collect only the minimum logs needed for
troubleshooting; logs and `docker inspect` output can contain private data.
Avoid posting raw output publicly:

```sh
# Service health and exit states.
docker compose -f docker-compose.yml ps --all

# Sample limited logs for one service; review locally for secrets.
docker compose -f docker-compose.yml logs --tail=50 elasticsearch

# Inspect mount targets on an *existing* service container to locate real data.
# Replace CONTAINER_ID with the actual value returned by docker ps.
docker inspect CONTAINER_ID --format '{{json .Mounts}}'
```

Verify with the application's own tooling that new events are ingested,
searchable, and preserved after a planned test-container recreation in a
**staging environment**. The historical `/Datak` mounts do not establish
persistence. `depends_on` only orders container startup and supplies no
application readiness guarantees.

## 3. Backup and rollback boundaries

1. Identify Elasticsearch's **actual** data location, manager/agent state,
   container bind mounts, index templates, dashboards, certificates and
   application config from a running installation. Do not assume the Compose
   host paths are sufficient.
2. Take an application-consistent backup using **vendor-compatible tooling**
   for the deployed version. Keep an immutable copy outside the Docker host.
3. Restore the backup into an isolated environment with matching binaries
   and verify event counts, query results, alert histories and authentication.
4. Record actual image digests, Compose model, configuration versions, IP
   allocations, backup timestamp, expected data loss window and rollback owner.
5. In a separate migration project, define a cutover window and acceptance
   gate. Never direct an older Elasticsearch binary at storage written by a
   newer indexer. Rollback requires a **matching old-version snapshot**.

**Never use `docker compose down -v` as a recovery shortcut**: volumes can be
irreversibly removed. Avoid blind service restarts or destructive rescans on
unbacked historical data.

## 4. Proposed supported replacement

Use the [official Wazuh Docker project](https://github.com/wazuh/wazuh-docker)
with currently maintained manager, indexer and dashboard components, private
networking, verified data volumes, authenticated TLS and a tested restore path.
Treat all Elastic Beats integrations as separately reviewed migrations.
See [docs/UPGRADE.md](UPGRADE.md) for migration phases and acceptance criteria.

## Maintenance quality policy

Before proposing changes to images, mounts, networks or capabilities, run
`make check` and review [the second audit](SECOND_AUDIT.md). CI rejects
unreviewed changes to the **resolved** Compose model. Do not print `docker
compose config` output from a production host into logs or public issues: it
may contain interpolated credential values. The automated validator consumes
JSON via a pipe and prints generic results only.
