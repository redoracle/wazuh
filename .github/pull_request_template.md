## Purpose and scope

<!-- Explain the motivation, what changed, and why this change is appropriate for a historical stack. -->

## Change classification

- [ ] Documentation/tooling or compatibility-preserving maintenance
- [ ] Runtime-affecting change (requires documented compatibility evidence)
- [ ] Platform migration (requires isolated staging and approved rollback plan)

## Verification performed

- [ ] `make test`
- [ ] `make compose-check` (no containers started)
- [ ] Manual config/security review of changed host/network privileges
- [ ] Staging ingest, alert, backup and restore tests **if runtime is changed**

## Security and rollback impact

<!-- Document changed image tags, published ports, host permissions, secret inputs,
volume targets, operational risk, vendor compatibility, and how to recover. -->

## Documentation

- [ ] README and operator documentation updated where behavior changed
- [ ] Architecture decision updated/added for significant changes
- [ ] No secrets, private host details or sensitive logs are included

> CI validates configuration syntax and regression contracts only. It does not
> certify that historical images are secure or that a running deployment works.
