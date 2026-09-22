from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from app.engine.context import ContextBuilder
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.report import ReportGenerator
from app.main import app
from app.models import Evidence, InvestigationRequest
from app.models import Hypothesis, HypothesisStatus


ALERT = {
    "alert_id": "finding_test_001",
    "source": "threatlens",
    "timestamp": "2026-09-21T10:00:00Z",
    "asset": {"hostname": "example.com", "ip": "93.184.216.34"},
    "finding": {
        "type": "http",
        "title": "Administrative endpoint observed",
        "severity": "medium",
        "evidence": {"status": 401, "url": "https://example.com/admin", "custom": "kept"},
    },
    "context": {"historical_alerts": [], "related_findings": [], "asset_inventory": None},
}


def request() -> InvestigationRequest:
    return InvestigationRequest.model_validate(ALERT)


def test_context_evidence_is_provenanced_and_unknown_input_is_preserved():
    context = ContextBuilder().build(request(), "INV-test")
    assert context.evidence[0].raw_reference == ALERT["alert_id"]
    assert any("custom" in evidence.metadata for evidence in context.evidence)
    assert context.evidence[0].confidence == 1.0


def test_evidence_confidence_is_bounded():
    with pytest.raises(ValidationError):
        Evidence(id="E-1", source="test", type="observation", finding="x", confidence=1.1, raw_reference="a")


def test_graph_serializes_and_links_evidence():
    graph = build_graph(ContextBuilder().build(request(), "INV-test"))
    data = graph.to_dict()
    assert data["nodes"]
    assert any(edge["relation"] == "supported_by" for edge in data["edges"])
    assert graph.find_by_type("evidence")


def test_hypotheses_are_deterministic_and_limited():
    context = ContextBuilder().build(request(), "INV-test")
    hypotheses = HypothesisEngine().generate(context, build_graph(context))
    assert len(hypotheses) <= 3
    assert all(0 <= hypothesis.confidence <= 1 for hypothesis in hypotheses)
    assert all(set(h.supporting_evidence) <= {e.id for e in context.evidence} for h in hypotheses)


def test_evaluator_marks_ambiguous_input_for_review():
    context = ContextBuilder().build(request(), "INV-test")
    hypotheses = HypothesisEngine().generate(context, build_graph(context))
    evaluation = EvidenceEvaluator().evaluate(context, hypotheses)
    assert evaluation.classification == "needs_investigation"
    assert evaluation.needs_investigation
    assert 0 <= evaluation.confidence <= 1
    assert evaluation.missing_evidence


def test_contradicting_evidence_reduces_confidence():
    context = ContextBuilder().build(request(), "INV-test")
    hypothesis = Hypothesis(
        id="H-1", title="test", description="test", supporting_evidence=["E-001"],
        contradicting_evidence=["E-002"], confidence=0.8, status=HypothesisStatus.plausible,
    )
    evaluation = EvidenceEvaluator().evaluate(context, [hypothesis])
    assert evaluation.confidence < hypothesis.confidence


def test_report_does_not_fabricate_mitre_or_actions():
    context = ContextBuilder().build(request(), "INV-test")
    graph = build_graph(context)
    hypotheses = HypothesisEngine().generate(context, graph)
    evaluation = EvidenceEvaluator().evaluate(context, hypotheses)
    report = ReportGenerator().generate(context, graph, hypotheses, evaluation)
    assert report.mitre_attack == []
    assert report.automated_action == "none"
    assert report.human_review_required


def test_api_complete_flow_and_missing_investigation():
    client = TestClient(app)
    assert client.get("/v1/health").json() == {"status": "ok"}
    created = client.post("/v1/investigations", json=ALERT)
    assert created.status_code == 201
    investigation_id = created.json()["investigation_id"]
    assert created.json()["classification"] == "needs_investigation"
    assert client.get(f"/v1/investigations/{investigation_id}").status_code == 200
    report = client.get(f"/v1/investigations/{investigation_id}/report")
    assert report.status_code == 200
    assert report.json()["automated_action"] == "none"
    assert client.get("/v1/investigations/INV-missing").status_code == 404
    assert client.get("/v1/investigations/INV-missing/report").status_code == 404


def test_api_rejects_invalid_input():
    client = TestClient(app)
    invalid = {**ALERT, "finding": {**ALERT["finding"], "severity": "unknown"}}
    assert client.post("/v1/investigations", json=invalid).status_code == 422
