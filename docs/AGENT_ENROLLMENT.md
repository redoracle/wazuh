# Secure agent enrollment: deployment and change-control runbook

**Classification:** security-sensitive operator procedure · **Scope:** Wazuh 4.14.9 single-host reference · **Status:** requires staging verification.

**New installations:** the repository template now requires `<use_password>yes</use_password>`, and `scripts/bootstrap.py` provisions a unique `config/generated/authd.pass` credential mounted read-only into `/var/ossec/etc/authd.pass`. The manager and enrollment secret must be verified in a running container; passing static CI is not enough. **Existing installations:** previously bootstrapped `config/generated/wazuh_manager.conf` and persistent volumes are not automatically changed. Plan a protected conversion with `scripts/enrollment_security.py --apply` and restart/recreate the manager only during an approved maintenance window. By default the agent ports still bind to loopback.

## Threat model and prerequisites

An exposed enrollment service can be targeted for unauthorized agent registration or enrollment abuse. A password is one control, **not** a substitute for authenticated/approved agent identity, source restrictions, certificate validation, agent inventory and monitoring.

Before enabling LAN enrollment, approve the source networks, agent identity lifecycle, credentials owner and rotation process; verify Wazuh's officially supported [password-authenticated enrollment procedure](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html) for the deployed version. **Do not enable public Internet exposure.** Only operators with approved Docker-host privileges should perform the steps below.

## Controlled staging change

1. Back up the manager state, `/var/ossec/etc/` (including `client.keys` and any existing `authd.pass`), the generated host-side manager configuration and the current `.env`; keep backups encrypted and **off-host**. Confirm rollback instructions before touching the deployment.
2. On an **existing** staging installation, first run `python3 scripts/enrollment_security.py` without `--apply` to check whether a conversion is required; review the recorded rollback point. Then run `python3 scripts/enrollment_security.py --apply` in an approved window. This creates a private 64-hex-character `config/generated/authd.pass`, changes only the single `<use_password>no</use_password>` element in the generated manager configuration, and saves the original as `config/generated/wazuh_manager.conf.pre-enrollment`. It will never rotate an existing password, overwrite an existing backup, or restart containers. **Do not** execute this on a live deployment without first taking and verifying external backups.
3. The main Compose file mounts `config/generated/authd.pass` as `/var/ossec/etc/authd.pass:ro` in the manager. Verify root/container UID/GID can read it and that Wazuh 4.x accepts the mount in staging. The file should remain private on the host (mode `0640`, under a `0700` generated directory); the vendor recommends `root:wazuh` and `0640` **inside** the container. A bind-mounted file's UID/GID may differ under rootless Docker/user namespaces; never fix that by making it world-readable. Securely distribute the shared enrollment secret to approved agents; do not print it to logs or store it in `.env`.

4. Recreate the Wazuh manager container during the approved window (`docker compose up -d --no-deps --force-recreate wazuh.manager`); verify the effective mount, permissions, auth behavior and startup. A simple reload may not apply newly mounted files. Do not force-recreate a manager if a protected data/queue backup has not been tested. Then confirm that the **effective** configuration now reports `<use_password>yes</use_password>` and that the password file is present with the intended ownership/mode. Confirm that manager startup and existing agents still function.
5. Enroll one **test** Linux/Windows agent using the supported vendor flow and an approved secret-distribution method. Verify the new agent appears correctly and sends expected events. Attempt enrollment with a wrong password and confirm that it is denied, while existing legitimate agents remain connected.
6. Open port `1515/tcp` only from explicit enrollment source networks, for the required period. Allow `1514/tcp` from approved agents as separately required; the Compose `AGENT_BIND_ADDRESS` setting currently applies to **both** ports. Use host/firewall rules to restrict each port independently. Leave manager API `55000/tcp`, indexer `9200/tcp` and dashboard administrative access restricted.
7. Record enrollment action, approver, affected agents, source/target firewall rules, denial evidence, and rollback point in a private change record. Rotate enrollment secrets through a vendor-tested process and revoke access for decommissioned agents.

## Verification (read-only inspection)

```bash
# On a prepared staging host only; avoid printing credentials or dumping the whole config.
docker compose ps
docker compose exec -T wazuh.manager sh -c "grep -A 12 '<auth>' /var/ossec/etc/ossec.conf | grep -E 'use_password|disabled|port'"
docker compose exec -T wazuh.manager sh -c 'stat -c "%U:%G %a" /var/ossec/etc/authd.pass'
# Inspect permitted host ports; the output must match your firewall change record.
docker compose port wazuh.manager 1515
```

If the expected `authd.pass` file or effective `<use_password>yes</use_password>` is missing, **close enrollment ingress and stop the change**. Do not fix a failed deployment by reverting to passwordless enrollment. The default project is a single-node example, so it does not provision an enrollment load balancer or redundant manager cluster.

## Rollback and incident response

Restore the known-good manager configuration **and** its matching persisted credentials from a verified backup. Close enrollment ingress if authentication fails or registration anomalies occur; preserve the manager's event records and affected agent identity evidence. Keep new registrations disabled until a security operator approves re-entry. In a Wazuh multi-node manager cluster, enrollment policy must be consistent on every participating manager.

Source: [Wazuh — using password authentication](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html) and [Wazuh enrollment troubleshooting](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/troubleshooting.html).
