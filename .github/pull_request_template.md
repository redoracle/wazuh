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
