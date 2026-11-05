# Wazuh — legacy Docker Compose stack

> **Status: historical, not production-ready or security-supported.** This repository
> preserves a 2019 Wazuh 3.10.2 and Elasticsearch/Kibana 7.3.2 deployment with
> Elastic Beats 7.4.2. Do **not** deploy it on untrusted networks. For a new
> deployment, use the [official Wazuh Docker stack](https://github.com/wazuh/wazuh-docker)
> and follow its current prerequisites, certificate, and credential instructions.

## Overview

The configuration defines ten services: Wazuh manager, Elasticsearch, Kibana,
Nginx, Packetbeat, Filebeat, Auditbeat, Journalbeat, Heartbeat, and Metricbeat.
All share a pre-existing external network `sll_net` and have statically assigned
`172.13.0.101`–`172.13.0.110` addresses. Several services mount host paths under
`/DATA/Wazuh` and request sensitive host access.

**This range is not private.** `172.13.0.0/16` is globally routable IPv4 space,
not RFC1918 private space. It must be replaced during migration. The repository
uses `expose:`, not `ports:`, so Docker Compose does not directly publish any
container ports on the host, although peers on `sll_net` may have access.

## Validation — no containers started

Run from the repository root:

```sh
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
docker compose -f docker-compose.yml config --quiet
```

The last command requires the Docker Compose v2 CLI plugin. Configuration
validation does not pull images, confirm image availability, test secrets, or
establish runtime security. CI performs the same checks for proposed changes.

## For operators of an existing isolated installation

1. Read [Security](SECURITY.md), [Architecture](docs/ARCHITECTURE.md), and
   [Migration and dependency audit](docs/UPGRADE.md) **before** running anything.
2. Inspect `docker network inspect sll_net` and confirm its address allocations
   won't conflict with another network or route. Do not create the historical
   public-range network on a production host.
3. Review the `/DATA/Wazuh` mounts, required Beat configuration files, and
   actual container storage paths. Historical `/Datak` targets are unchanged;
   **they are not verified persistent data directories** and must not be
   assumed to protect Elasticsearch or other application data.
4. Copy `.env.example` to `.env` only in a private working environment; set
   `NGINX_CREDENTIALS` using an approved secret source. Apply `chmod 600 .env`
   if writing credentials to that file. `.env` is Git-ignored but credentials
   may still be exposed to privileged inspectors or in shell history.
5. Inspect resolved settings with `docker compose config --quiet`, then in a
   *segregated lab only*, start with `docker compose up -d`. Validate actual
   authentication, ingestion, alerting, persistence, and restoration before
   considering any further use of these old images.

## Versioning and compatibility

The environment variables `WAZUH_STACK_TAG` and `BEATS_TAG` control image tags
across all four Wazuh images and all six Beats images respectively. Their
interpolation defaults preserve the exact pre-audit image versions without an
`.env` file. They do **not** make arbitrary newer tags compatible or safe.

The legacy stack must be rebuilt along the vendor-supported manager/indexer/
dashboard architecture, not upgraded by changing a tag alone. The migration
plan includes a backup inventory, staging acceptance criteria, and rollback
steps. [Read the upgrade decision and plan](docs/UPGRADE.md).

## Scope of the maintenance patch

- Removed deprecated Compose format version and legacy `links` (the shared
  user-defined network already provides DNS resolution by service name).
- Added read-only flags to Beat configuration and journal input mounts without
  changing host paths, fixed IPs, container images, or collector privileges.
- Centralized coordinated image tag defaults and documented a secret-safe
  local `.env` workflow.
- Added strict YAML and architecture regression tests, current CI tooling,
  scheduled dependency review, `.editorconfig`, security documentation, and
  a controlled platform migration guide.

This patch deliberately makes **no untested runtime image upgrades**. Static
checks do not replace functional staging tests or a security assessment.
