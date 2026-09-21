# ORION

Investigation Engine for SW4NIT LAB.

## Purpose

ORION consumes normalized ThreatLens alerts and produces deterministic, evidence-driven analyst reports. Stage 2 can query explicitly permitted existing data sources, but it does not launch scans or modify systems.

## Architecture

Reconix performs reconnaissance. Reconix Cloud orchestrates bounded scans and exposes Finding Schema 1.0. ThreatLens ingests, normalizes, and correlates findings. ORION receives that context:

```text
ThreatLens
    |
    v
Context Builder
    |
    v
Evidence Graph
    |
    v
Hypothesis Engine
    |
    v
Missing Evidence
    |
    v
Investigation Planner
    |
    v
Policy Engine
    |
    v
Tool Registry
    |---- ThreatLens Query
    |---- Reconix Results
    |---- MITRE Lookup
    |
    v
New Evidence -> Evidence Graph -> Hypothesis Re-evaluation -> Analyst Report
```

ArgusAgent is not part of ORION.

## Stage 1

Stage 1 validates input, builds context and a provenance-preserving evidence graph, generates up to three deterministic hypotheses, evaluates uncertainty, and produces a structured report. Confidence values are heuristic decision-support values and are not statistically calibrated probabilities.

## Stage 2: Controlled Investigation

Stage 2 adds a deterministic missing-evidence analyzer, planner, policy engine, tool registry, and bounded executor. The executor can query only:

- `threatlens.query`: retrieve one existing ThreatLens alert.
- `reconix.results`: retrieve results for an existing Reconix Cloud scan.
- `mitre.lookup`: look up an explicitly supplied MITRE technique in the small local catalog.

These tools are read-only and operate only on explicitly permitted data sources. Tool results become provenance-preserving evidence, the graph is updated, and hypotheses are evaluated again. Missing evidence and a query returning no results are represented separately.

Limits are enforced in code:

- maximum 5 investigation steps
- maximum 10 tool calls
- maximum 60 seconds using a monotonic clock
- bounded external responses

The planner cannot create arbitrary tool names or URLs. The registry fails closed for unknown tools. Tool arguments are typed per tool. `automated_action` remains `none`.

## Security Boundaries

ORION does not execute arbitrary commands, arbitrary Python, arbitrary URLs, arbitrary scans, arbitrary Reconix arguments, brute force, exploits, remediation, or infrastructure changes. It has no generic HTTP tool, shell tool, scan-submission path, or public tool-execution endpoint. API keys come only from environment configuration and are never returned in tool activity.

## API

- `GET /v1/health`
- `POST /v1/investigations`
- `GET /v1/investigations/{investigation_id}`
- `GET /v1/investigations/{investigation_id}/report`

Submit the safe sample:

```bash
curl -X POST http://127.0.0.1:8000/v1/investigations \
  -H "content-type: application/json" \
  --data @examples/sample_alert.json
```

The report contains evidence, hypotheses, missing evidence, tool activity, state, stop reason, uncertainty, and `automated_action: "none"`.

## Configuration

Copy `.env.example` to a local environment file and provide only explicitly configured integration values:

```text
MAX_INVESTIGATION_STEPS=5
MAX_TOOL_CALLS=10
MAX_RUNTIME_SECONDS=60
THREATLENS_BASE_URL=http://localhost:8000
THREATLENS_API_KEY=
RECONIX_CLOUD_BASE_URL=http://localhost:8080
RECONIX_CLOUD_API_KEY=
```

Values cannot bypass the hard safety ceilings. Empty integration URLs cause controlled tool denial rather than arbitrary network access.

## Local Development

```bash
python -m venv .venv
python -m pip install -e ".[test]"
uvicorn app.main:app --reload
```

Run tests and compile checks:

```bash
pytest -q
python -m compileall app
```

Tests use deterministic mock tools and do not require ThreatLens, Reconix Cloud, MITRE network access, API keys, or internet access.

## Docker

```bash
docker build -t orion:stage2 .
docker run --rm -p 127.0.0.1:8100:8000 orion:stage2
```

The image uses Python 3.12 slim, one Uvicorn worker, and a non-root user. Put Nginx or another controlled gateway in front of it for deployment.

## Current Limitations and Future Stages

Storage remains process-local and in memory, so results disappear on restart and are not shared between workers. The MITRE catalog is intentionally small and only contains techniques explicitly included in that local mapping. External adapters are read-only and require their services to be separately configured. Stage 3 functionality, autonomous agents, broad knowledge retrieval, and remediation are not implemented.
