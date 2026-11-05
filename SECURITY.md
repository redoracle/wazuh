# Security policy and legacy deployment boundaries

## Supported versions

| Component | Status | Security update policy |
| --- | --- | --- |
| Wazuh 3.10.2 / legacy Elastic 7 stack | **Unsupported** | No security patches are supplied by this repository; migrate to vendor-supported releases |
| Elastic Beats 7.4.2 | **Unsupported legacy integration** | No independently safe version bump is established |
| Test and CI tooling | Maintained as repository tooling only | Pinned versions, Dependabot reviews and GitHub Actions checks |

Do not use this repository as a way to receive vendor security patches.
**High-risk findings remain open** until a tested replacement exists; see the
[second audit](docs/SECOND_AUDIT.md) and
[threat model](docs/THREAT_MODEL.md).

**Warning:** This is a historical 2019 infrastructure configuration using
legacy Wazuh 3, Elasticsearch/Kibana 7.3-era images and Beats 7.4.2. It is not
an actively supported, security-certified product. Do not expose it to the
internet or run on untrusted, multi-tenant hosts. Prefer the supported upstream
[Wazuh Docker deployment](https://github.com/wazuh/wazuh-docker).

## Observed risks

- `172.13.0.0/16` is *not* a private network range. The external `sll_net`
  network may conflict with public routing and other Docker peers.
- Filebeat and Metricbeat mount `/var/run/docker.sock`. Even when mounted
  `:ro`, the Docker API endpoint may perform state-changing operations.
  Treat socket access as effectively host-root privilege.
- Auditbeat joins the host PID namespace and requests audit capabilities.
  Packetbeat/Metricbeat request additional network/inspection capabilities;
  Filebeat and Metricbeat run as root.
- Multiple host filesystem mounts allow access to sensitive data. `/Datak`
  mounts are not confirmed service persistence directories; backups based only
  on these paths may be incomplete.
- `NGINX_CREDENTIALS` is passed through the environment. The image's exact
  credential format, minimum permissions, and secret exposure need validation.
  Environmental secrets can be visible to privileged container inspectors.
- The repository does not demonstrate tested backups, TLS/certificate
  management, readiness probes, robust secret rotation, audit retention or
  runtime vulnerability scanning.

## Guardrails

Keep any existing stack isolated behind strict firewall controls, minimize
membership of `sll_net`, and prevent the Docker socket from being shared with
untrusted collectors. Keep `.env` outside version control; if it contains
secrets, restrict file permissions and do not print it in CI or support logs.
Back up and verify the *actual* application data paths. Treat collectors with
host privileges as requiring host-level trust. Use vendor-maintained container
images and documented migrations for new installations.

The current maintenance patch only makes suitable collector configuration and
journal inputs read-only and adds static tests; **it does not remove the
high-risk original privileges or make the stack production-safe**.

## Responsible reporting

Use GitHub's private vulnerability reporting capability **if enabled**, or
a verified non-public maintainer channel. We do not promise a response-time
SLA, embargo date, or security backport for unsupported vendor components.
Avoid publishing exploit steps or live credentials in public issues.

Do not publish credentials, host identifiers, working exploits, or private
infrastructure details in public issues. Contact repository maintainers via
an appropriate private channel or GitHub private vulnerability reporting
(if configured), and report vendor binary vulnerabilities to the vendor.

For remediation priorities, see [Upgrade and migration](docs/UPGRADE.md).
For non-destructive verification and recovery preparation, see the
[operator runbook](docs/OPERATIONS.md).

For branch protection and automated security policies, see the
[repository administrator checklist](docs/REPOSITORY_ADMIN.md).
