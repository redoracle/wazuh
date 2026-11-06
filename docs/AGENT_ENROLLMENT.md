# Secure agent enrollment: deployment and change-control runbook

**Classification:** security-sensitive operator procedure · **Scope:** Wazuh 4.14.9 single-host reference · **Status:** requires staging verification.

The shipped Wazuh manager template retains the upstream `<use_password>no</use_password>` setting. This is **not an enterprise-safe enrollment configuration if port 1515 is reachable from untrusted networks**. By default both agent ports are bound to `127.0.0.1`; widening the bind address without enrollment controls is a deliberate security change, not routine connectivity troubleshooting.

## Threat model and prerequisites

An exposed enrollment service can be targeted for unauthorized agent registration or enrollment abuse. A password is one control, **not** a substitute for authenticated/approved agent identity, source restrictions, certificate validation, agent inventory and monitoring.

Before enabling LAN enrollment, approve the source networks, agent identity lifecycle, credentials owner and rotation process; verify Wazuh's officially supported [password-authenticated enrollment procedure](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/using-password-authentication.html) for the deployed version. **Do not enable public Internet exposure.** Only operators with approved Docker-host privileges should perform the steps below.

## Controlled staging change

1. Back up the manager state, `/var/ossec/etc/` (including `client.keys` and any existing `authd.pass`), the generated host-side manager configuration and the current `.env`; keep backups encrypted and **off-host**. Confirm rollback instructions before touching the deployment.
2. On the **staging** manager, set `<use_password>yes</use_password>` inside the `<auth>` section of the effective `/var/ossec/etc/ossec.conf`. For a new instance, change `config/generated/wazuh_manager.conf` (not the tracked upstream template), then verify whether the image's configuration initialization applies the change. **Do not assume** that editing a read-only host mount changes an already-running manager's persistent `wazuh_etc` volume. Check the effective file *inside the container* after recreation/restart.
3. Create `/var/ossec/etc/authd.pass` **inside the manager's persisted configuration volume** via a secure operator channel. Per the vendor, use `root:wazuh` ownership and mode `0640`; avoid passwords on the command line, in `docker compose config`, shell history or tickets. A vendor-provided randomly generated enrollment password may be logged when the service restarts, so assess that disclosure risk before selecting that method.
4. Restart the Wazuh manager through the supported procedure and confirm that the **effective** configuration now reports `<use_password>yes</use_password>` and that the password file is present with the intended ownership/mode. Confirm that manager startup and existing agents still function.
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
