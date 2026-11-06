# AI integrations for Wazuh: engineering evaluation

**Reviewed:** 2026-11-06 · **Wazuh deployment:** [release-matched v4.14.9](../README.md) · **Status:** optional, human-supervised integrations. The default deployment does not launch AI services or give a model access to Wazuh.

## Recommendation

Start with **offline or read-only alert triage plus a local Ollama model** using the included [`triage.py`](../integrations/ai_triage/triage.py). It performs one bounded `POST /wazuh-alerts-4.x-*/_search` against the Wazuh **indexer API**, removes all fields except allowlisted alert metadata, and optionally sends only that projection to a locally hosted model. All results are advisory; analysts must corroborate them with primary evidence.

This design deliberately **does not** grant the model Manager API tokens, Docker socket access, Wazuh active-response permissions, or the ability to compose arbitrary indexer queries. It does not change the primary Wazuh deployment by default. See [hands-on guide](AI_HOWTO.md), [security](AI_SECURITY.md), and [validation](AI_VALIDATION.md).

## Approaches compared

| Approach | Availability / support | Data path | Capability | Principal risks | Recommendation |
| --- | --- | --- | --- | --- | --- |
| **Wazuh Cloud AI Analyst** | Official, *Wazuh Cloud* subscription feature; **not** a self-hosted `docker compose` component | Wazuh Cloud → AWS Bedrock/Anthropic processing according to vendor policy | Periodic alert, endpoint and vulnerability reports | Contractual/data-governance review; does not expose a local plugin | Cloud subscribers seeking managed reports |
| **Wazuh AI Assistant (OpenSearch/MCP gateway)** | Example maintained under `wazuh/integrations`; explicitly review version prerequisites and deployment as an integration project | Dashboard ML Commons → gateway → LLM/MCP → Wazuh APIs/indexer | Interactive threat hunting and potentially **agent-management actions** | Extensive permissions, remote provider disclosure, prompt injection, high operational complexity | Controlled pilot only, read-only tools first |
| **Ollama with constrained local triage (this repo)** | Independent, opt-in implementation; original integration code, not a Wazuh product | Narrow indexer read → schema projection → local Ollama → human review | Summarization and investigation hypotheses; no actions | Model hallucination, local resource usage, container/network trust, host-side audit handling | **Preferred starting point** |
| **Community Wazuh MCP servers** | Third-party projects; capabilities and maintenance vary | MCP client ↔ server ↔ indexer/Manager API | Natural-language tool access, telemetry and sometimes state changes | Tool inventory can contain write methods; auth/OAuth exposure; prompt-driven tool invocation | Review code, disable writes, isolate service and enforce RBAC before adoption |
| **Hosted ChatGPT/Claude alert enrichment** | Wazuh examples and commercial APIs, not an automatic part of Wazuh Docker | Alerts sent outside deployment | Summaries, prioritization, extraction | Sensitive logs/PII externalized, cost/retention/region, untrusted model output | Off by default; opt in only after legal/security approval and field minimization |
| **n8n / Mindflow / SOC orchestration** | Third-party services and workflow platforms | Workflow connector → Indexer/Manager APIs → LLM or ticketing | Ticket creation, human approvals, triage orchestration | Token proliferation, action workflows, workflow/plugin supply chain | Suitable later for human-approved ticket enrichment; do not enable auto-response initially |

**Privacy caveat:** Running Ollama locally avoids intentionally sending prompts to a hosted inference API, **provided model pulls, telemetry, egress routes and the actual runtime configuration are audited**. It does not automatically protect data against compromised local hosts, unexpected proxying, logging or prompt injection. MCP tool results can also contain sensitive data: using MCP does **not** guarantee that only abstracted logs reach the model.

## Facts that matter operationally

- The **Wazuh Manager API** (normally `55000`) manages Wazuh and agents; the **Wazuh Indexer API** (normally `9200`) is the supported source for querying indexed `wazuh-alerts-*` documents. Do **not** assume a `GET /alerts` Manager endpoint exists simply because a tutorial uses it. This project queries the indexer over TLS with a dedicated restricted principal.
- Upstream Wazuh's AI Assistant guide uses ML Commons, a gateway, and MCP tools; its documented agent-management flows are **outside the scope** of this read-only integration. Its published tested environment and prerequisites may differ from this repository's Wazuh 4.14.9 deployment. Integration against 4.14.9 **has not been demonstrated** here.
- Wazuh's agentic AI/Qwen3/Ollama blog explicitly calls its implementation a **proof of concept**. It is a useful architecture reference, not proof that the entire workflow is certified for production.
- Remote assistants can require an authenticated, internet-accessible MCP endpoint. Do not publish a Wazuh API or MCP server to the Internet merely to make a connector work.
- Wazuh Cloud AI Analyst's vendor privacy claims apply **to the Cloud service**, not automatically to independently configured third-party LLM connectors.

## Decision record

1. **Data origin:** read-only Indexer search; no Manager API, active response or arbitrary MCP tool calls.
2. **Data minimization:** include only timestamp, numeric rule ID and level, validated rule groups/MITRE technique IDs, and per-run HMAC-pseudonymized agent identifier; never send event body, file paths, usernames, IPs, command lines, file hashes or indexed raw logs to an LLM.
3. **Model:** explicit `--ollama` opt-in; only `http://127.0.0.1:11434` or private Compose DNS `http://ai-ollama:11434` are accepted by the client.
4. **Trust:** model output remains untrusted JSON; no runtime execution, no tools, no automated containment or Wazuh writes.
5. **Bounded workload:** 1–50 alerts, 1–60 minute windows, severity filter, 2–60 s timeout, strict request/response limits; failures fail closed.
6. **Transport:** Indexer TLS verification required against generated root CA; no `verify=False`, `curl -k`, HTTP downgrade, proxy environment, arbitrary redirects, or unfettered host URLs.

## Primary sources and implementation references

- [Wazuh AI Analyst — Wazuh Cloud documentation](https://documentation.wazuh.com/current/cloud-service/ai-analyst.html)
- [Wazuh Indexer API — reference](https://documentation.wazuh.com/current/user-manual/indexer-api/reference.html)
- [Wazuh indexer indices, including alert index patterns](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html)
- [Wazuh maintained AI Assistant integration example](https://github.com/wazuh/integrations/tree/main/integrations/AI_assistant)
- [Wazuh maintained ChatGPT integration example](https://github.com/wazuh/integrations/tree/main/integrations/ChatGPT)
- [Wazuh: Threat hunting with Agentic AI](https://wazuh.com/blog/threat-hunting-with-agentic-ai/)
- [Wazuh: Leveraging AI for threat hunting](https://wazuh.com/blog/leveraging-artificial-intelligence-for-threat-hunting-in-wazuh/)
- [SOCFortress Wazuh MCP Server (community)](https://github.com/socfortress/Wazuh-MCP-Server)
- [GenSecAI Wazuh MCP Server (community)](https://github.com/gensecaihq/Wazuh-MCP-Server)
- [Ollama local API](https://docs.ollama.com/api)
- [OpenSearch Security roles](https://docs.opensearch.org/latest/security/api/roles/create-role/)

These links are **references**, not imported code, endorsements, guarantees of compatibility or promises of future upstream maintenance. See [CI and live validation boundaries](AI_VALIDATION.md).
