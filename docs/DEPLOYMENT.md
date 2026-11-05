# Deployment guide

## Before first start

Use a new Docker Compose project with at least 4 CPU cores, 8 GB RAM and 50 GB disk. Install Docker Engine/Desktop with Compose v2, Python 3.11+, and Git. On Linux, set `vm.max_map_count=262144` in the active and persistent sysctl configuration. Reserve TCP `443`, `1514`, `1515`, and `55000` on the selected host interfaces.

This project creates a single-node deployment, not a multi-node failover cluster. Set up a controlled network, administrator access, a backup destination, and a trusted certificate plan **before opening host ports outside loopback**.

## Credentials and certificates

Create a Python virtual environment and install `requirements-bootstrap.txt`. Run:

```bash
python scripts/bootstrap.py
python scripts/bootstrap.py --check
```

The initializer uses cryptographic random bytes to create unique `INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`, and `API_PASSWORD`. It hashes the first two with bcrypt in `config/generated/internal_users.yml` and renders the dashboard API connection and manager configuration. It writes `.env` with mode `0600` and the generated folder with mode `0700`.

It is intentionally idempotent: running it a second time retains credentials. Partial initialization blocks further writes rather than risk mismatched passwords. **Do not delete generated files to rotate passwords on an active cluster.** Use the official indexer and API password rotation procedures and update all clients together.

Copy the generated `.env` and `config/generated/` securely to backup storage alongside generated certificates. `.env` and generated files must never be added to Git. Local generated configuration must be readable by the corresponding container processes when bind-mounted; the private host directory prevents unprivileged users from traversing to the files.

Generate TLS certificates with the official Wazuh generator:

```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

Certificates are stored in ignored `config/wazuh_indexer_ssl_certs/`. Verify the expected PEM filenames, ownership, and the dashboard certificate's browser trust properties. Never regenerate the CA casually for an existing installation: replacing certs without coordinated trust changes can interrupt communications.

## Configure network access

`DASHBOARD_BIND_ADDRESS`, `AGENT_BIND_ADDRESS`, and `API_BIND_ADDRESS` default to `127.0.0.1`. For remote dashboard access, prefer a VPN or SSH tunnel. For remote agents, set `AGENT_BIND_ADDRESS` to an appropriate private host interface and restrict source IPs with the host firewall. Enrollment is an especially sensitive interface; review certificate and authentication requirements before opening it. The indexer remains internal to the Compose network.

## Start and verify

```bash
docker compose -f generate-indexer-certs.yml config --quiet
docker compose -f docker-compose.yml config --quiet
docker compose up -d
docker compose ps
docker compose logs --tail=100 wazuh.indexer wazuh.manager wazuh.dashboard
```

Reach `https://localhost` (or the chosen interface). Login as `admin` with the private `.env` `INDEXER_PASSWORD`. Validate that manager, indexer and dashboard start, a test agent enrolls and sends data, an alert is indexed and searchable, and backup/recovery procedures work. Compose syntax passing does **not** prove image health or secure installation.

## Troubleshooting

- **Indexer fails to start:** Confirm host `vm.max_map_count`, available RAM/disk, certificate files and image architecture support.
- **Dashboard is not ready:** The indexer may still be initializing. Check `docker compose logs wazuh.dashboard wazuh.indexer` and credential consistency.
- **Certificate errors:** Ensure generated PEM files match hostnames in `config/certs.yml`, and use proper trust roots.
- **Login fails:** Verify initialization happened **before** first indexer start. The security index persists credentials; changing `.env` later does not change an already initialized indexer user database.
- **Remote agents cannot connect:** Confirm the bind address, host firewall, network routes and manager enrollment policy.

See [Operations](OPERATIONS.md) and [Wazuh's official Docker instructions](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).
