# Contributing to the Wazuh legacy configuration

This repository is a historical infrastructure reference. It is **not** a
supported production distribution, and passing CI does not certify old vendor
images. Changes should improve auditability and safe migration without hiding
or expanding legacy operational risk.

## Before opening a pull request

1. Read [SECURITY.md](SECURITY.md) and the
   [architecture decision](docs/decisions/0001-legacy-compatibility.md).
2. Classify the change:
   - **Maintenance:** tests, documentation, tooling, non-breaking YAML cleanup.
   - **Runtime-affecting:** image tags, IPs, host mounts, privileges, data
     paths, service dependencies, credentials, listener behavior, or resources.
   - **Migration:** a separately planned target stack with version-supported
     data transfer, rollback, security acceptance and a staging test report.
3. Do not combine a routine maintenance PR with a major Wazuh/Elastic migration.
4. Do not commit passwords, tokens, certificates/private keys, `.env` files,
   real IPs of private infrastructure, logs containing credentials, or data.
5. Update the README/runbook and explicit regression contracts when a
   legitimate change alters expected topology or deployment behavior.

## Local quality gate

Requires Python 3.11+ and (for Compose validation) Docker Compose v2.

```sh
python -m pip install -r requirements-dev.txt
make check
```

`make lint` compiles test/validator Python. `make test` runs offline YAML,
service-security, adversarial mutation and documentation checks.
`make compose-check` verifies Compose syntax; `make resolved-check` validates
the interpolated security contract without pulling or starting images. Do not substitute these checks for a staging
security review or workload-level integration tests.

## Review checklist

- The PR explains *why* the change is safe, the compatibility impact, and
  the exact tests run.
- Changed Wazuh/Beats image versions include a vendor-supported compatibility
  matrix, staged ingest/alert tests, image digest records, and a rollback plan.
- Increased host capabilities, socket access, mounts, or public ports require
  explicit security review. Removal of existing collector privileges also
  requires a functional collector test; failing closed is not automatically
  functionally equivalent.
- Changed data paths require proof of persistence, backup, **restore**, and
  migration, not just a successful container startup.
- All local Markdown links resolve, no sample secrets are real, and all test
  and workflow changes retain least-privilege permissions.

## Repository conventions

- See the [second audit](docs/SECOND_AUDIT.md) for prioritized findings,
  dependency decisions and unresolved risks.
- Run the [required CI checks](docs/REPOSITORY_ADMIN.md) on Python
  3.11/3.13/3.14 and Docker Compose before merge; repository rulesets are
  configured in GitHub Settings, not enforced by this Markdown file.

- Use two-space YAML indentation and four-space Python indentation.
- Pin CI actions to immutable commit SHAs and annotate their reviewed versions.
- Keep `.env.example` synthetic and leave `.env` ignored by Git.
- Prefer concise, reproducible commands over instructions that automatically
  deploy, mutate or destroy old production data.
- Document architectural trade-offs in `docs/decisions/` before changing the
  legacy compatibility boundary.

Issues or public PRs must never include exploit details, credentials, private
agent identifiers, or production configuration dumps. See the private
reporting guidance in [SECURITY.md](SECURITY.md).
