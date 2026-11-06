# TLS certificate lifecycle and operator verification

This deployment uses Wazuh's release-aligned certificate generator with Wazuh manager, Indexer and dashboard certificates. These are **self-signed/private-CA credentials**, not an automatically managed enterprise PKI. Expiry, hostname verification, key permissions, rotation and revocation are operator responsibilities.

## Offline verification before opening any management interface

After [deployment bootstrap](DEPLOYMENT.md) and certificate generation, run from the deployment host:

```bash
python3 scripts/check_certificates.py --min-days 30
# For auditable, key-free machine-readable check results:
python3 scripts/check_certificates.py --json
```

The check is **read-only**. It uses the local `openssl` binary, requires the expected public certificates and private keys, checks that the cert directory is not world-searchable, and flags private keys accessible to `other` users and verifies each certificate matches its private key. It also checks each certificate's expiry headroom and verifies service certificate trust and host identity against `root-ca.pem`. No key or certificate contents are printed. The command fails closed if certificates are missing, near expiry, invalid or inaccessible.

**Important compatibility note:** The upstream certificate generator can produce filesystem modes that require post-generation permissions review. Tighten file/directory permissions in a manner compatible with the **actual container UID/GID and read-only bind mounts**; `chmod 600` on every key without checking container access can break service startup. The script verifies only world-access for keys, not group membership or the safety of Docker administrators. A passing result is **not** proof that host/agent browsers trust the CA, and does not replace TLS handshake tests with live containers.

## Rotation runbook (staging first)

1. Inventory the active CA and certificate serials, expiration dates, SANs, key owners and every dependent TLS client. Record Wazuh version, certificate-tool version and current image digests in your protected change record.
2. Plan trust overlap and dependency order for Indexer, Manager, Filebeat, Dashboard, agent ingress and any reverse proxy. Use organizational PKI and the upstream-compatible file layout; rotation must preserve configured DNS names such as `wazuh.indexer` where applicable.
3. Back up existing TLS materials and corresponding service credentials in an encrypted, access-controlled location. **Never** publish private keys in tickets or CI artifacts. Never overwrite the live CA or keys without a rollback plan.
4. Replace certificates in an **isolated staging deployment**, verify that bind-mounted paths and owners/modes remain accessible to each container, and check trust and hostname validation without `-k`, `verify=False` or disabling hostname checks.
5. Exercise Wazuh Manager indexing, Dashboard-to-Indexer, Dashboard-to-Manager API calls, agent enrollment/telemetry, and a restart/recreate of every dependent container. Validate Indexer and Wazuh API functionality and alert ingestion.
6. Run `python3 scripts/check_certificates.py --min-days 30`, and collect certificate expiry, denied/wrong-CA connectivity and rotation evidence in a private system. Obtain peer approval before production scheduling.
7. During cutover, monitor ingestion gaps, TLS handshake errors, and certificate expiry alerts. Revoke/retire superseded keys according to approved policy after confirming all clients switched trust anchors. Exercise recovery with the old materials **only** if the rollback decision point remains valid.

## Common failures

| Failure | Investigation |
| --- | --- |
| Certificate check cannot find PEM | Confirm certificate generator completed and local paths match `config/wazuh_indexer_ssl_certs/` (no symlink redirection) |
| Hostname/trust failure | Check SAN, approved CA and the exact service DNS name; don't disable TLS verification |
| Permission failure | Verify owner/GID/mount access in staging; private keys should never be world-readable |
| Near-expiry warning | Request approved reissue immediately; rotate before the remaining validity violates your security policy |
| Browser trust warning | Dashboard's private CA may not be trusted; distribute the enterprise CA through managed endpoint trust stores, not by making insecure exceptions |

See [enterprise readiness](ENTERPRISE_READINESS.md), [security policy](../SECURITY.md), [backup/restore](BACKUP_RESTORE.md) and the [official Wazuh Docker certificate guidance](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html).
