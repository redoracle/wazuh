# AI integration validation, acceptance, and incident response

## What CI proves

The repository's GitHub Actions matrix runs Python syntax checks and offline unit tests for Python 3.11, 3.13 and 3.14. It also renders the **base and opt-in overlay Compose configurations** without starting containers. Offline tests cover schema filtering, bounded read-only search, TLS context creation, endpoint allowlists, adversarial fields, model output parsing and bounded size, audit minimalism, fail-closed errors, and no-network file mode.

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q scripts tests integrations
# After normal Wazuh bootstrap (config files and .env exist):
docker compose -f docker-compose.yml -f docker-compose.ai.yml config --quiet
```

**CI does not prove:** successful connection to a real Wazuh 4.14.9 indexer; OpenSearch Security permissions; model inference quality; absence of host/container vulnerabilities; successful model download; network egress restrictions; resource sizing; incident response suitability; production HA; accuracy on real alerts; or Wazuh data retention compliance. No runtime Wazuh alerts or secrets are sent to GitHub Actions.

## Production-gate checklist (operator-executed)

- [ ] Confirm actual central-component version, index pattern `wazuh-alerts-4.x-*`, alert timestamp mapping and TLS certificate SAN against the deployment.
- [ ] Create the **dedicated Indexer role and internal user**; verify allowed bounded alert search and rejected query to non-alert indices, rejected writes, rejected role/agent-management calls. Never test destructive actions against production; perform authorization tests in staging.
- [ ] Validate that `local-secrets` and model/audit storage have suitable owner, mode, encryption at rest and retention limits, and that no secret appears in Compose output, system logs, stdout or CI artifacts.
- [ ] Confirm the model and worker images, digests, software bills of materials and vulnerabilities meet organization policy; review model license and provenance. A release tag is not an immutable digest.
- [ ] Test model accuracy using **sanitized, human-labeled** alerts representing expected severity distribution, false positives, MITRE group labels and adversarial log content. Measure precision, recall, unsupported claims, latency, token utilization and refusal behavior before routing decisions to analysts.
- [ ] Red-team malformed API responses, huge alert fields, source-content prompt injection, model output injection, inaccessible model, expired CA, unauthorized Indexer principal and network egress failures. Confirm no Wazuh actions are generated or executed.
- [ ] Confirm only intended internal network paths exist. Specifically, `ai-ollama` must not be able to reach `wazuh.indexer` or `wazuh.manager`; neither the indexer nor the model should expose a host-facing port.
- [ ] Observe CPU/RAM pressure, JVM heap and Wazuh ingest latency with AI enabled; move inference to separate hardware if resource contention affects security telemetry.
- [ ] Have an analyst sign off the output format, evidence-verification SOP, escalation rules, data classification and incident auditing before regular use.
- [ ] Document on-call owner, credential rotation, disaster recovery, model update validation, failure modes, rollback and user access control.

## Deterministic quality benchmark

Create a local, de-identified fixture set with known verdicts (`true_positive`, `false_positive`, `unknown`) and expected rule/MITRE mappings. For each model revision, run the same fixture set offline with bounded parameters, and have independent analysts score:

| Metric | Proposed minimum acceptance criterion |
| --- | --- |
| Raw sensitive field exposure to model | **0** values from banned field list |
| Automatic operational actions | **0** (none implemented) |
| Model transport outside local approved endpoints | **0** requests |
| Unsupported indicators/commands presented as observed evidence | **0** |
| Format/schema compliance | 100% on accepted responses; invalid responses fail closed |
| Analyst-reviewed alert rule/level preservation | 100% in metadata projection |
| Precision/recall & mean latency | Define and approve deployment-specific baseline; no fabricated benchmark here |

CI's passing fixtures measure **code-level contracts only**, not meaningful detection accuracy. “0 unsupported facts” must be assessed with human-labeled evaluations; it is not a claim achieved by the current model.

## Daily process

1. Execute the CLI at a documented cadence under an operator account or supervised scheduler. Keep concurrency low and avoid overlapping large searches.
2. Retain bounded audit metadata and alert summaries only under policy-approved encrypted storage. Rotate audit files; the script appends and does not implement log rotation.
3. Have a SOC analyst compare each advisory to Wazuh indexer source records before triage, escalation or a ticket is finalized.
4. If output is malformed, suspicious, overconfident, or a model endpoint is unreachable, turn off `--ollama` and continue using the deterministic metadata-only workflow.
5. To disable model inference immediately, stop `ai-ollama` using the overlay command in [HOWTO](AI_HOWTO.md). This does **not** stop Wazuh Manager, Indexer or Dashboard.

## Rollback

Because the integration is **opt-in and adds no Wazuh state mutations**, stop the model service, stop running the worker, revoke the dedicated Indexer reader principal, and remove the overlay from invocations. Validate that the original Wazuh Compose stack remains healthy. Keep audit logs for the approved retention period; do not run `docker compose down -v`.
