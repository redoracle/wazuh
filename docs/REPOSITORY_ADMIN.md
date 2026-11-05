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
