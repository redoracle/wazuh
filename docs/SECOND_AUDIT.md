# Second engineering and security audit

**Audit date:** 2026-11-05
**Scope:** repository source, Docker Compose model, development dependencies,
CI/CD workflow, operational docs, GitHub contribution workflows and historical
security posture.
**Method:** manual source review; pinned dependency/release verification;
offline unit and adversarial contract tests; GitHub Actions Compose validation.
No legacy images were started, pulled or vulnerability-scanned. Findings about
runtime behavior require separate lab verification.

> [!IMPORTANT]
> **Passing this audit does not make Wazuh 3 production-safe.** The repository
> is a maintenance/reference project, not a supported Wazuh distribution.

## Executive decision

- **Safe to update in this PR:** documentation, test infrastructure, read-only
  policy checks, CI supported Python runtime coverage, contribution governance,
  and supply-chain audit records.
- **No compatible release upgrade proved:** Wazuh 3/Elastic 7 images and all
  six legacy Beats are retained unchanged. Modern Wazuh has different
  manager/indexer/dashboard semantics and data formats.
- **No new runtime risk introduced:** the ten-container Compose baseline has
  not been re-architected. The security validator rejects new published ports,
  container privileges, mounts, capabilities, image versions and networks.
- **Cannot guarantee from CI:** Docker image vulnerabilities, agent enrollment,
  alert quality, credential protection, storage correctness, or restore safety.

## Prioritized findings

| ID | Severity | Finding and evidence | Treatment | Status |
| --- | --- | --- | --- | --- |
| A-01 | **Critical** | Wazuh `3.10.2_7.3.2` and Beats `7.4.2` are an obsolete, integrated platform (`docker-compose.yml`) | Separate vendor-supported migration, snapshot and functional tests | **Open—migration required** |
| A-02 | **High** | `172.13.0.0/16` is public IPv4 space on an external Docker network | IPs contract-checked; private RFC1918 redesign only in migration | **Open—compatibility constraint** |
| A-03 | **High** | Filebeat/Metricbeat Docker socket mounts, Auditbeat host PID, extra Linux caps and root collectors | Prevent permission expansion; isolate host and restrict socket trust | **Open—privileges preserved** |
| A-04 | **High** | `/Datak` host bind targets may not persist application data; no restore proof | Explicit preflight/no-go gate and backups in runbook | **Open—runtime evidence required** |
| A-05 | **High** | Environment-based `NGINX_CREDENTIALS` may expose credentials and has unverified legacy handling | Ignore `.env`, use synthetic CI values, never print interpolated configuration | **Open—replace in migration** |
| A-06 | Medium | Original static checks only parsed the unexpanded Compose file | Add resolved-JSON validator and mutation tests, fail closed on privilege/topology changes | **Fixed in this PR** |
| A-07 | Medium | CI covered one Python runtime and only one Compose syntax check | Python 3.11/3.13/3.14 matrix, exact model validator, `pip check`, bounded job timeouts | **Fixed in this PR** |
| A-08 | Medium | No managed issue forms, support expectations, release notes or repo-admin standards | Add issue forms, support policy, changelog and repository settings checklist | **Fixed in this PR** |
| A-09 | Medium | `master` lacked branch protection at audit time | Document required reviews/checks and restrict direct pushes in GitHub Settings | **Owner/admin action required** |
| A-10 | Low | No cross-platform line ending policy | Add `.gitattributes`, source-hygiene checks | **Fixed in this PR** |

## Version decisions and verifiable upgrade inventory

| Dependency | Current committed version | Available target / decision | Safe change made |
| --- | --- | --- | --- |
| Wazuh legacy four-image family | `3.10.2_7.3.2` | Official Wazuh Docker `v4.14.9` is a **different platform**; `v5.0.0-rc2` is pre-release. No approved direct upgrade from Wazuh 3 demonstrated | **No**: existing tag preserved |
| Elastic Beats (six legacy components) | `7.4.2` | Upgrades must be validated with the search backend and event integrations. Journalbeat is not a safe drop-in replacement | **No**: existing tag preserved |
| PyYAML, *test-only* | `6.0.3` | PyPI lists `6.0.3` as its latest stable release at audit time | **Already current** |
| GitHub Actions checkout | `v7.0.1`, commit `3d3c42e...` | Pinned immutable full SHA, GitHub-hosted runners | **Already current** |
| GitHub Actions setup-python | `v7.0.0`, commit `5fda3b95...` | Pinned immutable full SHA, GitHub-hosted runners | **Already current** |
| Python interpreter (tests, not application) | CI 3.13 | Add supported 3.11 LTS baseline and 3.14 coverage without changing any running container | **Yes: expanded CI** |

The repository has **no application package manifest**, so dependency upgrades
refer to infrastructure images and test/CI tooling only. Dependabot proposes
weekly updates for Python tooling and GitHub Actions; Docker updates are
**deliberately excluded** to prevent automatic breaking migrations.

Sources checked on 2026-11-05:

- [Wazuh Docker releases](https://github.com/wazuh/wazuh-docker/releases)
- [Wazuh upgrade guide and compatibility](https://documentation.wazuh.com/current/upgrade-guide/index.html)
- [Wazuh central component rollback warnings](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html)
- [Wazuh Docker upgrade instructions](https://documentation.wazuh.com/current/deployment-options/docker/upgrading-wazuh-docker.html)
- [PyYAML stable release history](https://pypi.org/project/PyYAML/)
- [GitHub Actions secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use)

## Verification matrix

| Gate | Automated? | Can it certify a production deployment? |
| --- | --- | --- |
| Duplicate-key rejection and correct GitHub Actions YAML parsing | Yes, offline Python | No |
| Compose service/image/IP/mount/privilege baseline | Yes, YAML tests and resolved JSON model | No |
| Adversarial privilege/port/network/image mutations | Yes, offline Python | No |
| Three-version supported Python test matrix | Yes, GitHub Actions | No |
| Compose interpolation/syntax without image pull | Yes, GitHub Actions | No |
| Documentation links, examples, repo hygiene | Yes, offline Python | No |
| CVE scanning of historical images | No | Required in isolated migration lab |
| TLS/credentials, ingestion, backups, restore | No | Required in isolated migration lab |

## Merge and migration acceptance gates

This PR can merge once the latest GitHub Actions runs are green, security
review has accepted preservation of legacy risks, and the PR diff shows no
untested runtime changes. Do not deploy an unsupported stack on the strength
of CI alone. See [repository administration](REPOSITORY_ADMIN.md) for
branch/ruleset settings that must be enabled in GitHub UI.

**A separate migration PR must provide** a supported target version and
compatible component matrix, immutable image digests, a private network plan,
minimal collector privileges, verified persistent volumes and snapshots,
TLS/certificate and secret flows, rollback rehearsal, and **running**
integration tests of ingestion, alerting and dashboard access. See
[upgrade plan](UPGRADE.md), [operator runbook](OPERATIONS.md) and
[threat model](THREAT_MODEL.md).
