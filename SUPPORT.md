# Support boundaries

This is an **unmaintained historical deployment architecture**, now with
maintenance-oriented documentation and static validation. It is not an
official Wazuh release, commercial service, production installation guide,
or source of security patches for old vendor containers.

## What can be discussed here

- Documentation corrections, broken links, offline tests and CI behavior.
- Reproducible issues in the checked-in Docker Compose *model* without
  connecting to production systems or disclosing private information.
- Review of the documented migration decisions or reproducible improvements
  to security and compatibility checks.

Use the repository's [issue forms](.github/ISSUE_TEMPLATE/config.yml) for
non-sensitive reports. Provide sanitised reproduction steps, expected versus
observed behavior, and whether the issue is about the repository, not vendor
binaries. There is no guaranteed response or resolution time.

## What this repository cannot support

- Live Wazuh deployments, security patching of obsolete containers, private
  incident response, or emergency support.
- Authentication credentials, certificates, agent identifiers, production
  logs or network diagrams sent through public GitHub issues.
- Arbitrary updates from Wazuh 3 / Elastic 7 to a modern release by tag change.

For current Wazuh support and deployment guidance, consult the
[upstream documentation](https://documentation.wazuh.com/current/) and
[official Docker project](https://github.com/wazuh/wazuh-docker).
Report vulnerabilities privately under [SECURITY.md](SECURITY.md).
