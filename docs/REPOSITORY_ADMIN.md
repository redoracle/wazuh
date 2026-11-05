# Repository administration and required GitHub settings

> This is an administrator checklist, **not** evidence the settings are active.
> GitHub repository settings cannot be enforced by a Markdown file. The owner
> must inspect them in the GitHub UI and record their actual status.

## Repository identity

- Use a description such as **"Historical Wazuh 3 Docker Compose configuration —
  unsupported reference, security audit and migration guidance"**.
- Add topics such as `wazuh`, `docker-compose`, `legacy`, `security-audit` and
  `migration` (avoid suggesting the project is an official Wazuh distribution).
- Set the default branch to `master` until an intentional branch rename is
  planned; a rename must update CI and issue links.
- Keep the MIT repository license and explain that upstream image licenses are
  separate; do not add vendor-owned logos or imply vendor sponsorship.

## Recommended ruleset for `master`

Under **Settings → Rules → Rulesets** (or branch protection):

1. Require a pull request before merging, with at least one independent review
   where an additional maintainer is available. A solo-maintainer repository
   should not require its owner to self-approve through CODEOWNERS.
2. Require current successful CI checks: `Python contracts (3.11)`,
   `Python contracts (3.13)`, `Python contracts (3.14)` and
   `Compose model and security contract`.
3. Require resolved conversations and prohibit force pushes and branch
   deletion. Require branches to be up-to-date with `master` if the release
   process needs strict merge validation.
4. Use squash merges by default for focused maintenance changes. Require
   review before any changes to `.github/workflows/`, privileged mounts,
   image tags, `.env` handling or network configuration.
5. Restrict bypass privileges to designated administrators and record any
   emergency override in a follow-up issue.

## Actions and supply chain

- **Settings → Actions → General:** set the default `GITHUB_TOKEN` permission
  to **read-only**; restrict workflows to explicitly trusted actions and
  require **full-length SHA pinning** if that policy is available.
- Avoid `pull_request_target` for executing untrusted code and never write
  secrets into CI jobs triggered by fork pull requests.
- Verify Dependabot alerts and security updates are enabled, and review its
  weekly Python/GitHub Actions PRs before merging.
- Do not configure Dependabot auto-merging or Docker image auto-bumps for the
  legacy vendor stack. Changes must be version-aware, with independent
  ingestion, index/data, rollback and security tests.
- Consider secret scanning and push protection (subject to GitHub plan and
  feature availability), and enable **private vulnerability reporting** if
  supported. Keep reports private until responsibly triaged.

## Issue and support management

- Confirm `.github/ISSUE_TEMPLATE/` forms render properly and direct security
  reports to the private security policy rather than a public issue.
- Review stale issues periodically. Do not publish dashboards, agent IDs,
  production config dumps or credentials in public discussions.
- Link [support boundaries](../SUPPORT.md), [security policy](../SECURITY.md),
  and [contribution guide](../CONTRIBUTING.md) prominently.

## Verification checklist

An administrator should record, in a private or appropriately sanitized issue,
which settings are active, the date, owner, and required status check names.
CI status checks on an unprotected branch do **not** prevent a manual merge.

Related: [second audit](SECOND_AUDIT.md) and
[GitHub Actions security documentation](https://docs.github.com/en/actions/reference/security/secure-use).
