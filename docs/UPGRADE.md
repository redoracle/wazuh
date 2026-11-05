# Dependency audit and controlled upgrade strategy

## Baseline audit — November 5, 2026

| Component | Version in original repository | Decision |
| --- | --- | --- |
| Wazuh manager, Elasticsearch, Kibana, Nginx | `3.10.2_7.3.2` | **Hold together.** Major vendor-platform migration required. |
| Elastic Beats: Packetbeat, Filebeat, Auditbeat, Journalbeat, Heartbeat, Metricbeat | `7.4.2` | **Hold together.** No backwards-compatible upgrade proven against this cluster. |
| PyYAML (new, test-only) | `6.0.3` | Pinned to latest checked stable release. |
| GitHub Actions checkout (new) | `v7.0.1` | Current stable release, pinned to its immutable commit SHA. |
| GitHub Actions setup-python (new) | `v7.0.0` | Current stable release, pinned to its immutable commit SHA. |

The original repository contained no package manifest, application source, or
dependency lockfile. Its actual versioned dependencies are container images.
The legacy Wazuh images encode an Elasticsearch/Kibana integration contract.
Updating one of them in place, or updating Beats without validating its
Elasticsearch API and index templates, could cause outages and data corruption.

Vendor release guidance identifies stable Wazuh Docker `v4.14.9` and a newer
manager/indexer/dashboard architecture. Wazuh 5.x is a separate major series;
its appearance in release catalogs does not establish safe compatibility with
this Wazuh 3 stack. These are **point-in-time** findings, not perpetual update
advice. Check vendor guidance again before migration.

- https://github.com/wazuh/wazuh-docker/releases
- https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html
- https://www.elastic.co/docs/deploy-manage/deploy/self-managed/installing-elasticsearch

## Pre-migration inventory

Document the *running* image digests (not just tags), Wazuh agent versions,
rule sets, index templates, data retention, endpoint destinations, ingestion
rates, secrets/certificates, and all host mount paths. Determine whether
`/Datak` contains actual persistent data; the configuration alone cannot
establish this. Capture baseline dashboard/search and alert events.

## Safe migration phases

1. **Backup and proof of recovery.** Stop writes or take consistent snapshots
   using the existing application's supported procedure. Preserve manager
   configuration/state, indices, certificates, credentials and dashboard
   exports. Restore a copy in a segregated test environment to demonstrate
   that the backup is useful.
2. **Build a supported target.** Choose the specific stable vendor release,
   review the vendor's *supported* Wazuh 3 upgrade path and deployment
   prerequisites, and provision fresh certificate and secret handling. Do not
   point a new indexer directly at old Elasticsearch data directories.
3. **Isolated data and configuration migration.** Migrate via supported
   version-aware export/import/reindex tooling. Validate user permissions,
   detection rules, event semantics and historical searches. Replace the
   public-range static addressing with an RFC1918 plan.
4. **Telemetry integration.** Verify each Beat replacement or Elastic Agent
   and its outputs against the destination. Do not assume Journalbeat has a
   drop-in current equivalent. Reduce collector host privileges and retire
   Docker socket mounts wherever functionality permits.
5. **Acceptance checks.** Require enrollment, agent traffic, example alert
   generation, new and historical search, dashboard login, least privilege,
   certificate validity, health signals, backups, restore, and image security
   scans to pass before cutover.
6. **Controlled cutover.** Establish change owners, outage window,
   monitoring, a rollback decision point and retention policy. Keep the old
   system isolated and non-writing until the integrity and recovery criteria
   are met.

## Verification and rollback

The added CI only runs YAML/contract tests and `docker compose config --quiet`:
**it does not start images, perform CVE scans, prove certificates, or run live
integration tests**. Production changes need a staging deployment and an
independent security/recovery review.

Record current image digests, all effective configuration, network settings,
real data locations, and a recoverable snapshot before making changes. **Do not
run `docker compose down -v` during recovery.** If migration fails, restore a
verified snapshot to *matching old binaries* in isolation. Never start old
Elasticsearch code against volumes already mutated by a newer indexer.

### Deferred work / decisions

- Legacy image versions should be replaced, but no image bump can be certified
  safe from this repository's evidence. This is a platform-migration project.
- Validate real persistence destinations and replace `/Datak` only when
  backed by an image-aware test and a backup procedure.
- Migrate old collector privileges, static IPs and secret delivery as an
  intentionally reviewed architectural change, not an implicit refactor.
- Dependabot can propose future *test and CI tooling* upgrades, but does not
  substitute for manual Wazuh/Beats compatibility and runtime checks.
