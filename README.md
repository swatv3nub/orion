# ORION

Investigation Engine for SW4NIT LAB.

## Architecture

```text
Reconix -> Reconix Cloud -> ThreatLens -> ORION -> Investigation -> Analyst Report
```

Reconix performs reconnaissance. Reconix Cloud manages bounded scans and exposes Finding Schema 1.0. ThreatLens ingests, normalizes, and correlates findings. ORION consumes those alerts and runs one bounded investigation pipeline:

```text
ThreatLens alert
    -> Context Builder
    -> Evidence Graph
    -> Hypothesis Engine
    -> Missing Evidence
    -> Investigation Planner
    -> Policy Engine
    -> Tool Registry
    -> ThreatLens / Reconix results / MITRE
    -> New Evidence
    -> Hypothesis Re-evaluation
    -> LLM Analyst Assessment (optional)
    -> Analyst Report
```

ArgusAgent is not part of ORION.

## Stages

### Stage 1

Stage 1 validates normalized alerts, builds a provenance-preserving context and evidence graph, generates deterministic hypotheses, evaluates uncertainty, and produces a structured analyst report. Confidence values are heuristic decision-support values, not statistically calibrated probabilities.

### Stage 2: Controlled Investigation

Stage 2 adds missing-evidence analysis, deterministic planning, policy checks, a fail-closed tool registry, and a bounded executor. Only these read-only tools exist:

- `threatlens.query`: query one existing ThreatLens alert.
- `reconix.results`: retrieve results for an existing Reconix Cloud scan.
- `mitre.lookup`: look up an explicitly supplied technique in the local catalog.

Limits are hard-bounded in code: 5 steps, 10 tool calls, and 60 seconds. Tool results become new evidence and hypotheses are re-evaluated.

### Stage 3: Live Lab Integration

Stage 3 adds a typed ThreatLens client and the `POST /v1/investigations/from-alert/{alert_id}` integration path. ORION fetches an existing configured ThreatLens alert, validates and adapts it to the existing Stage 1/2 input model, preserves Reconix metadata such as `scan_id` and `finding_id`, and invokes the existing `InvestigationService`.

When a trusted `scan_id` is present, the existing read-only Reconix results tool can retrieve `/api/v1/scans/{scan_id}/results`. ORION never creates a scan or accepts a target from this endpoint.

### Stage 5: LLM Analyst Assistance

ORION optionally sends the already-collected investigation context to Gemini for a structured analyst assessment. Gemini `gemini-3.5-flash-lite` is the default provider, with OpenAI and then OpenRouter/Nemotron fallback for transient failures. OpenAI uses low reasoning effort. If all configured providers fail, ORION returns its deterministic report as `partial`.

The LLM cannot select or execute tools, create evidence, start scans, remediate findings, or alter deterministic evidence, hypotheses, correlations, or classification. Every factual LLM claim and hypothesis statement must reference ORION evidence IDs; unknown evidence or hypothesis IDs reject the assessment. Human review remains required when evidence is missing and `automated_action` is always `none`.

## API

- `GET /v1/health`
- `POST /v1/investigations`
- `POST /v1/investigations/from-alert/{alert_id}`
- `GET /v1/investigations/{investigation_id}`
- `GET /v1/investigations/{investigation_id}/report`

Direct normalized-alert example:

```bash
curl -X POST http://127.0.0.1:8000/v1/investigations \
  -H "content-type: application/json" \
  --data @examples/sample_alert.json
```

Live configured-alert example:

```bash
curl -X POST http://127.0.0.1:8000/v1/investigations/from-alert/finding_demo_001
```

The live endpoint accepts only an alert ID. It does not accept URLs, targets, commands, tool names, or credentials.

## Configuration

Use environment variables or a local uncommitted `.env`:

```text
THREATLENS_BASE_URL=http://localhost:8000
THREATLENS_API_KEY=
THREATLENS_CONNECT_TIMEOUT_SECONDS=5
THREATLENS_READ_TIMEOUT_SECONDS=15

RECONIX_CLOUD_BASE_URL=http://localhost:8080
RECONIX_CLOUD_API_KEY=
RECONIX_CLOUD_CONNECT_TIMEOUT_SECONDS=5
RECONIX_CLOUD_READ_TIMEOUT_SECONDS=30

MAX_INVESTIGATION_STEPS=5
MAX_TOOL_CALLS=10
MAX_RUNTIME_SECONDS=60

LLM_PROVIDER=gemini
LLM_MAX_INPUT_BYTES=100000
LLM_MAX_OUTPUT_TOKENS=2048

GEMINI_API_KEY=
GEMINI_BASE_URL=https://generativelanguage.googleapis.com/v1beta
GEMINI_MODEL=gemini-3.5-flash-lite

OPENAI_API_KEY=
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-6-luna

OPENROUTER_API_KEY=
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=nvidia/nemotron-3-super-120b-a12b:free
```

Integration base URLs come only from configuration. Responses are bounded, redirects are not followed, and API keys are never included in reports or errors. Empty integration URLs produce controlled tool failures.

## Security Boundaries

ORION does not execute arbitrary commands or Python, fetch arbitrary URLs, proxy arbitrary HTTP, launch scans, accept Reconix arguments, brute-force, exploit, remediate, or modify infrastructure. There is no generic tool-execution endpoint. Unknown tools fail closed, PolicyEngine runs before every tool call, `automated_action` remains `none`, and human review remains required when evidence is insufficient.

## Development

```bash
python -m venv .venv
python -m pip install -e ".[test]"
uvicorn app.main:app --reload
```

Run deterministic tests and compile checks:

```bash
pytest -q
python -m compileall app
```

The test suite mocks the ThreatLens and Reconix HTTP boundaries. It does not require live services, internet access, credentials, or external OSINT providers.

## Docker

```bash
docker build -t orion:stage3 .
docker run --rm -p 127.0.0.1:8100:8000 orion:stage3
```

The container uses Python 3.12 slim, one Uvicorn worker, a non-root user, and no host mounts, privileged mode, Docker socket, database, broker, or extra infrastructure.

## Limitations

Investigation storage remains process-local and in memory. The MITRE catalog is intentionally small. Live end-to-end testing requires separately configured ThreatLens and Reconix Cloud services. Production multi-tenant persistence, autonomous remediation, arbitrary scanning, external OSINT, and unrestricted agents are not implemented. ORION has not been claimed as deployed to SW4NIT LAB.
