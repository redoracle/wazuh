# Repository administration

The files in `.github/` are proposals for developer workflow and reporting. Administrators must enable GitHub-hosted controls separately:

1. Require the CI workflow to pass before merging into the default branch.
2. Require at least one independent code review and dismiss stale approvals when new commits arrive.
3. Enable secret scanning and push protection where supported.
4. Enable Dependabot security alerts and automatic dependency PR creation.
5. Enable private vulnerability reporting and direct affected Wazuh image issues to the vendor.
6. Restrict direct pushes and force-pushes; protect release tags and signing policies.
7. Review Actions permissions, runner isolation, the default `GITHUB_TOKEN` scope and third-party action updates.
8. Establish an owner and response policy for maintenance, releases, security advisories, and backup restoration.

All containers and generated credentials are deliberately **excluded** from hosted CI runtime tests. CI verifies configuration and bootstrap contracts but cannot replace an operator's staging environment.

## Required master protection and verification

This repository's `master` requires an administrator-enforced branch ruleset/branch protection before enterprise promotion. Enable at least one independent review, enforce on admins, block force pushes and deletion, require resolved review conversations, and require current PR CI checks: `Python and bootstrap contracts (3.11)`, `(3.13)`, `(3.14)` and `Docker Compose configuration`. Use a ruleset compatible with Dependabot and with the organization's security scanning and code-owner policies. Require secret-scanning/push-protection where available.

After enabling controls, a credentialed repository administrator can run the **read-only** `python3 scripts/check_github_governance.py` with `GH_TOKEN` in a private environment. The check never prints the token, fails closed when it cannot read protection settings, and checks key review/status parameters; it does **not** prove the controls are effective for every bypass actor, nor does it enable them. Retain evidence privately.
