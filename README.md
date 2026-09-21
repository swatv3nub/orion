# ORION

Investigation Engine for SW4NIT LAB.

## Purpose

ORION turns a normalized ThreatLens alert into a deterministic, evidence-driven analyst report. It does not scan targets, execute tools, or remediate systems.

## Architecture

Reconix discovers security observations. Reconix Cloud executes and normalizes scans as Finding Schema 1.0. ThreatLens ingests and correlates those findings. ORION receives the resulting alert and runs:

`input validation -> context builder -> evidence graph -> hypothesis engine -> evidence evaluator -> analyst report`

Stage 1 is a deterministic evidence-analysis foundation. Autonomous investigation tools are intentionally not enabled.

## Stage 1 Components

- **Context Builder:** converts supplied observations into provenance-preserving evidence.
- **Evidence Graph:** an in-memory Python graph of alerts, assets, findings, and evidence.
- **Hypothesis Engine:** deterministic HTTP and generic finding rules, capped at three hypotheses.
- **Evidence Evaluator:** bounded heuristic confidence, missing evidence, uncertainty, and classification.
- **Report Generator:** structured analyst output. Recommended steps are not executed.

Evidence distinguishes observed facts from interpretations and hypotheses. Unknown evidence is represented as missing, never invented. Confidence values are heuristic decision-support values and are not statistically calibrated probabilities.

## Relationships

ORION consumes ThreatLens context; it does not replace Reconix or Reconix Cloud. Reconix remains the reconnaissance system, Reconix Cloud remains the scan execution and Finding Schema 1.0 boundary, and ThreatLens remains the normalization and initial correlation layer. ArgusAgent is not part of ORION.

## API

- `GET /v1/health`
- `POST /v1/investigations`
- `GET /v1/investigations/{investigation_id}`
- `GET /v1/investigations/{investigation_id}/report`

Example:

```bash
curl -X POST http://127.0.0.1:8000/v1/investigations \
  -H "content-type: application/json" \
  --data @examples/sample_alert.json
```

The response contains an investigation ID, `completed` status, and a classification. The report endpoint returns evidence, hypotheses, missing evidence, uncertainty, and `automated_action: "none"`.

## Security Boundaries

Stage 1 only reasons over supplied data. It cannot execute shell commands or arbitrary code, fetch URLs, scan targets, launch Reconix, access networks, exploit systems, modify infrastructure, or perform remediation. No external service or secret is required.

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

## Docker

```bash
docker build -t orion:stage1 .
docker run --rm -p 127.0.0.1:8100:8000 orion:stage1
```

The image uses one Uvicorn worker and runs as a non-root user. Put Nginx or another controlled gateway in front of it for deployment.

## Current Limitations and Future Stages

Stage 1 uses process-local in-memory storage, so results disappear on restart and are not shared between workers. Confidence is heuristic. The graph and pipeline are ready for future controlled planning and policy boundaries, but Stage 2 tools, autonomous loops, external integrations, and persistence are not implemented.
