# Self-hosted AI-assisted Wazuh operations

**Reviewed:** 2026-11-06 · **Base deployment:** Wazuh [4.14.9](../README.md) · **Implementation:** optional, independently maintained Python CLI and local Ollama; not a native Wazuh AI feature.

This guide describes **only functionality implemented in this repository or supported by documented self-hosted APIs**. A passing offline test does not establish that the live integration or its model's security conclusions have been validated on a real Wazuh installation. There is no automatic incident response, built-in chatbot, autonomous threat hunter, or model-driven agent management.

## What is actually available

| Self-hosted capability | Implemented here | Evidence / verification | Limitations |
| --- | --- | --- | --- |
| **Offline metadata triage** | Python 3.11+ [`triage.py`](../integrations/ai_triage/triage.py) processes a bounded synthetic JSONL fixture with no network and no model | Deterministic unit tests and reproducible [offline HOWTO](AI_HOWTO.md#1-offline-dry-run--no-docker-no-model-no-network) | Provides an alert summary, **not** detection or validated threat attribution |
| **Read-only Wazuh Indexer alert search** | Fixed HTTPS `POST /wazuh-alerts-4.x-*/_search` with restricted time, severity and result count; optional Docker overlay | Official [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html) and [alert index names](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html); requests and TLS tested with mocks | **Live Wazuh 4.14.9 connection and reader-role authorization not tested in CI**; operator must verify in staging |
| **Local Ollama inference** | Explicit `--ollama` option calls Ollama's local `/api/chat` endpoint with **only filtered metadata** and parses bounded JSON output | Documented [Ollama API](https://docs.ollama.com/api); prompt construction, response parsing and endpoint restrictions exercised in offline tests | **A downloaded model's inference quality, latency, resource usage and image integrity are not CI-verified** |
| **Human-supervised investigation** | Results contain an untrusted advisory and `human_review_required: true`; model has no tools or Wazuh write API | Code paths and regression tests ensure no commands or Wazuh operations are dispatched | Analyst must independently investigate the original events in Wazuh; model output is not evidence |

All functionality is **opt-in**. The ordinary `docker compose up -d` continues running only the Wazuh manager, indexer and dashboard. The model container has no published host port and is not joined to the Wazuh application network. The bridge worker connects to both networks and remains a sensitive trust boundary; isolation depends on host, Docker and network policy.

## Recommended operating pattern

1. **Start with deterministic offline review.** Run a synthetic alert through the CLI with no model and verify that secrets, user names, hostnames, full logs, IP addresses and commands never appear in its report.
2. **Use a dedicated Indexer account.** Its role must permit only the required search operation on `wazuh-alerts-4.x-*`; test the actual role permissions in staging. The CLI's metadata filtering is **not** a substitute for Indexer-side RBAC or optional field-level security.
3. **Enable Ollama only for human-readable hypotheses.** Select and inspect a local model; review its license and deployment footprint. Treat every generated recommendation as a possible hallucination or instruction-injection artifact.
4. **Keep incident actions outside the AI process.** No automatic blocks, agent actions, shell execution, index writes, case updates or configuration changes. Require independent evidence and existing SOC approval processes.
5. **Validate before regular use.** Test TLS, user-role denial rules, model responses, data minimization, CPU/RAM pressure and fail-closed paths. See the [acceptance checklist](AI_VALIDATION.md).

## Security and privacy boundaries

- The worker sends only timestamp, numeric rule ID/level, validated rule groups, MITRE technique identifiers and a per-run pseudonymized agent reference to Ollama. This is **still potentially sensitive security metadata**; protect output and container/network traffic.
- The Indexer reader **may be able to retrieve raw indexed alert fields** even though this CLI requests and forwards only a small projection. Enforce the smallest available index action group (`search`), consider field-level security where supported, protect the credential and verify permissions independently.
- The Ollama endpoint is restricted in code to `127.0.0.1`, `localhost` or the private Compose service `ai-ollama` on port `11434`; the indexer endpoint must use TLS and a trusted CA. The worker disables ambient HTTP proxies and redirects. **Neither rule is a substitute for firewall and egress controls.**
- Starting Ollama and fetching models can require network access; **self-hosted does not mean air-gapped**. Review model artifacts, image digests, network policy, resource limits and logs before use.
- Confidence labels generated by an LLM are **not calibrated detection scores**. Evaluate summaries and hypotheses with a human-labeled local test set before using them in your SOC workflow.

## Deliberately not provided

This repository does **not** ship an MCP server, autonomous SOC agent, natural-language query planner, dashboard chatbot, external inference adapter, threat-response executor or agent administration capability. Such additions would require a separate code/security review and version-specific runtime verification. Do not infer those features from Wazuh's general AI articles, integration examples or community projects.

## Implementation and independent references

- [Operational HOWTO](AI_HOWTO.md) — from synthetic data through a dedicated reader and optional local Ollama.
- [Architecture and threats](AI_SECURITY.md) — trust boundaries, alert-field minimization, model and credential risks.
- [Validation and incident response](AI_VALIDATION.md) — exact evidence available today and the outstanding live acceptance gates.
- [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html) and [Wazuh alert indices](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html) — vendor-documented local query capabilities.
- [OpenSearch Security action groups](https://docs.opensearch.org/latest/security/access-control/default-action-groups/) and [role permission verification](https://docs.opensearch.org/latest/security/access-control/permissions/) — server-enforced least privilege.
- [Ollama API reference](https://docs.ollama.com/api) — local model API contract; model behavior remains unverified until a real inference test.

The sources document **APIs and authorization primitives**, not a Wazuh-endorsed, production-certified AI service. All integration-specific code is maintained independently in this repository.
