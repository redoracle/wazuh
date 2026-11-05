# Release management and upgrade procedure

The deployment is **pinned to Wazuh Docker v4.14.9**, verified as the latest stable upstream release on 5 November 2026. The three service images, manager configuration, dashboard configuration, indexer configuration and certificate tool must form a compatible **release set**.

Do not blindly change image tags to `latest`, a release candidate or a new major version. The official Docker repository is the version authority:

- [Wazuh Docker releases](https://github.com/wazuh/wazuh-docker/releases)
- [Official Wazuh Docker upgrade documentation](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html)

## Controlled upgrade checklist

1. **Select a stable tag** and check vendor release notes, image availability, supported Docker host architectures, manager/indexer/dashboard interoperability and any required certificate-tool changes.
2. **Inventory the running platform:** image digests, Wazuh agent versions, indexed data and version, manager configuration, users/roles, TLS materials and all volumes.
3. **Create verified backups:** consistent indexer snapshots, manager state, custom rules, dashboard state, generated secrets and certificates. Test restoration in isolation.
4. **Review the upstream tag as a whole.** Update all three product image tags and their matching configuration mounts, security schemas and compatible certificate generator. Record the tag and source provenance in `NOTICE.md` and `CHANGELOG.md`.
5. **Prepare an isolated staging deployment** with copies of production data using the vendor-supported migration path. Do not mount production volumes into a newer indexer without explicit compatibility guidance.
6. **Verify** TLS and authentication, API permissions, new and existing agent ingestion, alert creation, search, dashboard function, persistence and rollback readiness. Run automated repository CI and staged image-based integration tests.
7. **Cut over** during an approved window with an owner, outage budget and explicit rollback decision point. Monitor indexing, CPU/memory/disk, API latency and alerts afterward.

The initial bootstrap generator provisions **new** indexer accounts. It does not rotate the security database of a live cluster. Use upstream password-rotation tooling for already-running deployments.

## Rollback boundary

An older indexer may not read data files migrated by a newer release. If tests fail after migration, restore an independent, verified pre-upgrade snapshot to **matching previous binaries**. Never attempt a downgrade by launching old containers against data already written by a newer indexer.

## Dependency policy

- `bcrypt==5.0.0` and `PyYAML==6.0.3` are explicit pinned host/test dependencies, reviewed weekly by Dependabot.
- CI actions are pinned by immutable Git commit SHA and monitored by Dependabot.
- Wazuh container versions and the generator are managed **as a single release bundle**, not as individually auto-upgradable libraries.
- Runtime vulnerability management includes host/container patching, exposure reduction, monitoring, image provenance verification and the vendor's current security advisories.
