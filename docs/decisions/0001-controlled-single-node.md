# ADR 0001 — Separate a controlled single-host reference from enterprise HA

- **Status:** Accepted, 2026-11-06
- **Scope:** Wazuh 4.14.9 single-node Compose and optional local AI triage

## Context

The repository implements upstream-compatible single-node Wazuh components with credentials and TLS. Runtime deployment and HA are not verified by GitHub-hosted CI. Calling this enterprise-ready would imply resiliency and recoverability that a single Docker host cannot provide.

## Decision

Retain this Compose stack as a **controlled single-host reference** and improve non-disruptive safety checks. Expose two machine-readable readiness profiles: `controlled` validates source-level contracts; `enterprise` intentionally reports missing HA, recovery evidence, signed governance and staged runtime acceptance as blockers. Adopt the vendor's documented multi-node distribution for enterprise availability requirements rather than inventing an unsupported overlay.

We rotate Docker stdout/stderr logs with bounded `json-file` retention and cap the short-lived AI triage worker's resources. We do not change version-sensitive Indexer disk settings or enrollment authentication behind operators' backs; these require vendor-compatible staged procedures.

## Consequences

Passing controlled CI is not deployment certification. Enterprise approval depends on a documented architecture, independent hosts, real failover and restore tests, access restrictions, monitoring, incident ownership, supported upgrades and change governance. The [readiness standard](../ENTERPRISE_READINESS.md) and [acceptance guide](../PRODUCTION_ACCEPTANCE.md) define the exit conditions.
