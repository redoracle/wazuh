# Changelog

This repository documents a legacy deployment; it does not publish versioned
container images or pretend to maintain the upstream Wazuh binaries.

## Unreleased — repository maintenance (2026-11-05)

### Repository quality

- Rebuilt the README with architectural context, unsupported-version warnings,
  configuration options, validation commands and operational links.
- Added operating, upgrade, threat-model, governance and audit documentation,
  contributor and conduct policies, issue forms, and a PR template.
- Added static YAML/service regressions, offline mutation tests, and a
  resolved Docker Compose JSON security-contract validator.
- Added multi-Python CI, immutable GitHub Actions SHA pins, Dependabot for
  development tooling, and standard source formatting configuration.

### Compatibility and security

- Removed deprecated Compose `version` and `links` while preserving the
  original ten-service architecture and image versions.
- Retained original image defaults, public-range IPs, mounts and privileged
  collector settings; marked remaining risks explicitly as **unresolved**.
- Changed selected collector input/configuration mounts to read-only.

### Not done

- No Wazuh/Elastic container upgrades, live tests, certificate provisioning,
  vulnerability scan, storage repair or production migration.

See the [second audit](docs/SECOND_AUDIT.md) and
[upgrade strategy](docs/UPGRADE.md) for decisions and remaining gates.
