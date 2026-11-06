## Summary

Describe what changes, why it is needed, and the Wazuh release or vendor reference when relevant.

## Safety and compatibility

- [ ] Wazuh manager/indexer/dashboard versions remain a coordinated release set.
- [ ] Ports, TLS, credentials, volume persistence and image provenance were reviewed.
- [ ] No `.env`, generated file, private key or real customer data is included.
- [ ] Breaking changes include migration, backup and rollback instructions.

## Verification

- [ ] Python unit tests passed.
- [ ] Docker Compose configuration validated with initialized local test credentials.
- [ ] Staging image/runtime validation performed when service behavior changes (or explicitly documented as not performed).

## Documentation

Link changed README, architecture, operations or upgrade guidance as applicable.

## Enterprise change gate

- [ ] `make preflight` passed; all reported warnings were understood.
- [ ] Enterprise-level blockers are documented, not waived by static CI.
- [ ] Image changes include approved digests/provenance and vulnerability scan evidence.
- [ ] Any runtime-impacting change has staged onboarding/indexing, backup/restore and rollback results or is explicitly marked unverified.
- [ ] README, security and runbooks reflect the behavior actually implemented.

See [enterprise readiness](https://github.com/redoracle/wazuh/blob/master/docs/ENTERPRISE_READINESS.md) and [production acceptance](https://github.com/redoracle/wazuh/blob/master/docs/PRODUCTION_ACCEPTANCE.md).

- [ ] `make docs-check` passed for documentation changes, including local anchor targets.
- [ ] Certificate, enrollment or backup instructions include operator ownership, failure handling and matching upstream sources.
