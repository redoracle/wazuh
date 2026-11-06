# HOWTO — private Wazuh alert triage with local AI

[Back to AI evaluation](AI_INTEGRATIONS.md) · [Threat model](AI_SECURITY.md) · [Validation](AI_VALIDATION.md)

This is an **opt-in, read-only** workflow for the Wazuh v4.14.9 Docker deployment. No AI service is started with ordinary `docker compose up -d` and no Wazuh configuration is edited by the integration. Start offline, then grant access to a narrowly scoped Indexer account only when you have a real operational need.

## 1. Offline dry run — no Docker, no model, no network

Prerequisite: Python 3.11+. Generate one synthetic alert whose timestamp falls within the default 15-minute window:

```bash
python3 - <<'PY'
from datetime import datetime, timezone
import json
with open('/tmp/wazuh-ai-synthetic.jsonl', 'w', encoding='utf-8') as output:
    output.write(json.dumps({
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'rule': {'id': '100123', 'level': 12, 'groups': ['authentication_failed'],
                 'mitre': {'id': ['T1110']}},
        'agent': {'id': '001'},
        'full_log': 'THIS FIELD WILL NEVER BE INCLUDED IN AI OUTPUT',
    }) + '\n')
PY
python3 integrations/ai_triage/triage.py \
  --source file --input-file /tmp/wazuh-ai-synthetic.jsonl \
  --max-alerts 10 --minutes 15 --min-level 10
```

Check that `advisory.provider` is `none`, `human_review_required` is `true`, and neither `full_log` nor any secret or identifying agent name appears. The CLI **never invokes a model without `--ollama`**.

## 2. Prepare Wazuh and a least-privileged Indexer account

1. Complete the base [Wazuh deployment guide](DEPLOYMENT.md) and generate the indexer TLS certificates. Confirm the main stack is healthy.
2. In **Wazuh Dashboard → Indexer management → Security** (menu names vary by upstream version), use the supported OpenSearch Security UI/API to create a **new** role `wazuh_ai_alert_reader`. Set **no cluster or tenant permissions**, and grant only the `read` index permission on `wazuh-alerts-4.x-*`. You may choose a narrower index pattern and field-level security (FLS) policy where supported. Do not include `wazuh-archives-*` or broad `wazuh-*` patterns.
3. Create a dedicated internal user `wazuh-ai-reader`, give it a unique random password, and map **only** the new role to it. Do **not** reuse `admin`, `kibanaserver`, or `wazuh-wui` credentials. Follow upstream [OpenSearch role and user instructions](https://docs.opensearch.org/latest/security/access-control/users-roles/). Role/user changes must be made through the **running** security index, not by editing the initial `config/generated/internal_users.yml` bootstrap file.
4. Verify the account can perform a bounded search on alert indices, **cannot** access non-alert indices, and **cannot** write, delete, manage roles or execute Manager API actions. Do not proceed if negative authorization tests have not been performed.

Example restricted role shape (create through Security UI or approved authenticated admin API, not via a repo-managed bootstrap step):

```json
{
  "cluster_permissions": [],
  "index_permissions": [
    {
      "index_patterns": ["wazuh-alerts-4.x-*"],
      "allowed_actions": ["read"]
    }
  ],
  "tenant_permissions": []
}
```

The `read` action group is granted by OpenSearch Security. Prefer even narrower individual read actions and field-level security when operationally feasible; test any such restrictions against your actual Wazuh/OpenSearch version. The **CLI itself does not confer read-only rights**; these must be enforced server-side.

## 3. Store the AI reader password privately

```bash
mkdir -p -m 0700 local-secrets local-state
# Enter the AI reader password through a hidden prompt. Do not paste into shell history.
python3 - <<'PY'
import getpass, os
from pathlib import Path
p = Path('local-secrets/ai-indexer-password')
if p.exists():
    raise SystemExit('Password file already exists; refusing to overwrite')
value = getpass.getpass('Dedicated Wazuh AI reader password: ')
if not value or '\n' in value or '\r' in value:
    raise SystemExit('Empty or invalid password')
fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write(value)
PY
```

These paths are ignored by Git. Restrict local Docker access, backups and shell access; Docker operators can read secrets mounted into a container. Never store the password in `.env`, commit it, embed it in Compose command arguments or share it with a model.

## 4. Query the Wazuh Indexer using the opt-in worker

The **main** Compose deployment intentionally publishes no Indexer host port. The optional overlay attaches the worker to the Docker project network so it can reach `https://wazuh.indexer:9200` without publishing `9200` externally. TLS is verified against `config/wazuh_indexer_ssl_certs/root-ca.pem`.

```bash
# Confirm the base installation was initialized and Wazuh is already running.
python3 scripts/bootstrap.py --check
docker compose ps

# Compose overlay only; does not enable the AI model.
docker compose -f docker-compose.yml -f docker-compose.ai.yml config --quiet

docker compose -f docker-compose.yml -f docker-compose.ai.yml \
  run --rm --no-deps ai-triage
```

Expected output is a JSON report containing only **timestamp, numeric rule ID/level, validated groups, MITRE technique IDs and a per-run pseudonymized agent reference**. No raw event body reaches the worker's output or its optional model prompt. The worker performs one fixed, bounded `_search` call. The local audit log (`local-state/audit.jsonl`) contains only run metadata, not alert bodies or generated report contents.

**Important:** By design the worker's `python:3.13-slim` runtime is a moving upstream image tag. For regulated deployments, review the current image, pin an approved digest, run image scanning and maintain a patch process before production use. The model image is version-tagged but must also be vulnerability-scanned.

## 5. Optional: local Ollama reasoning (no hosted LLM API)

The overlay includes an optional **Ollama v0.40.15** service on a separate AI-only network. It has **no host-published port** and **no direct network attachment to Wazuh**. Image/model downloads require operator-approved egress; verify model licensing and its provenance before pulling.

```bash
# Start a local private Ollama service.
docker compose -f docker-compose.yml -f docker-compose.ai.yml up -d ai-ollama

# Fetch a vetted model into the dedicated model cache. Adjust model/size to your hardware.
docker compose -f docker-compose.yml -f docker-compose.ai.yml \
  exec ai-ollama ollama pull qwen3:8b

# Explicitly enable the model; still READ ONLY, without automatic response actions.
docker compose -f docker-compose.yml -f docker-compose.ai.yml \
  run --rm --no-deps ai-triage \
  --source indexer --indexer-url https://wazuh.indexer:9200 \
  --ca-file /certs/root-ca.pem --user wazuh-ai-reader \
  --password-file /run/secrets/ai-indexer-password \
  --audit-file /state/audit.jsonl \
  --minutes 15 --max-alerts 10 --min-level 10 \
  --ollama --ollama-url http://ai-ollama:11434 --model qwen3:8b
```

CPU-only 8B inference can be slow. Verify memory, CPU/GPU capacity and runtime latency on your host; adding an LLM to the same small Docker host increases contention with the indexer and can degrade alert processing. Prefer separate dedicated inference hardware for persistent operations.

### Review the report

1. Confirm `human_review_required: true` and `advisory.untrusted: true`.
2. Use exact Wazuh alert timestamps, numeric rule IDs and the indexer/dashboard to investigate primary evidence independently.
3. Check for hallucinated conclusions, MITRE mapping errors, insufficient context and any attempted instruction injection.
4. Escalate through your existing SOC case-management process. **Never** execute copied commands or Wazuh active responses solely because the model suggested them.
5. Keep raw evidence and analyst notes in your approved protected case-management system, not in AI output or the audit JSONL.

## Troubleshooting

| Symptom | Likely cause / safe check |
| --- | --- |
| No alerts | Check time window (1–60 minutes), `--min-level` and actual alert indices; empty output is not proof the environment is clean |
| `403` or search error | Confirm the dedicated role mapping grants `read` only for the intended alert index; do not swap in administrator credentials |
| TLS handshake error | Regenerate/verify the Wazuh CA using the supported process; inspect DNS/hostnames; do not disable TLS verification |
| Model unavailable | Verify `ai-ollama` health, availability of the selected local model and available RAM; omit `--ollama` to retain deterministic metadata triage |
| Unexpected Docker permissions | Ensure `local-secrets` exists and the password is an accessible regular file; never relax to world-readable permissions |
| Missing model response | Bounded timeout or JSON validation failure; no partial model answer is accepted |
| Resource pressure | Stop Ollama and inspect indexer latency; consider separating inference workload from the Wazuh host |

To stop the local model without touching Wazuh:

```bash
docker compose -f docker-compose.yml -f docker-compose.ai.yml stop ai-ollama
```

Do not run `down -v`: it deletes persistent volumes. Production acceptance steps are in [AI validation](AI_VALIDATION.md).
