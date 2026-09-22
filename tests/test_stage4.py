from app.engine.context import ContextBuilder
from app.engine.correlator import EvidenceCorrelator
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.missing import MissingEvidenceAnalyzer
from app.engine.report import ReportGenerator
from app.models import Evidence, InvestigationContext, InvestigationRequest

from tests.test_stage1 import ALERT


def evidence(kind: str, finding: str, **metadata) -> Evidence:
    return Evidence(id=f"E-{kind}-{finding}", source="reconix_cloud", type=kind, finding=finding, confidence=1.0, raw_reference="scan-1", metadata=metadata)


def context_with(*items: Evidence) -> InvestigationContext:
    request = InvestigationRequest.model_validate(ALERT)
    return InvestigationContext(
        investigation_id="INV-stage4",
        primary_alert=request,
        asset=request.asset,
        evidence=list(items),
    )


def test_correlates_scan_finding_asset_and_network_observations():
    context = context_with(
        evidence("finding_observation", "finding", scan_id="scan-1", finding_id="finding-1", hostname="example.com"),
        evidence("scan_result", "same finding from scan", scan_id="scan-1", finding_id="finding-1", hostname="example.com"),
        evidence("port_observation", "port 80 open", scan_id="scan-1", hostname="example.com", port=80),
        evidence("port_observation", "port 443 open", scan_id="scan-1", hostname="example.com", port=443),
        evidence("dns_observation", "DNS record", scan_id="scan-1", hostname="example.com"),
        evidence("http_observation", "HTTP 200", scan_id="scan-1", hostname="example.com", status=200),
        evidence("tls_observation", "TLS certificate", scan_id="scan-1", hostname="example.com", certificate="present"),
        evidence("subdomain_observation", "www.example.com", scan_id="scan-1", hostname="www.example.com"),
    )
    result = EvidenceCorrelator().correlate(context, build_graph(context))
    types = {relation.relationship_type for relation in result.relationships}

    assert "same_scan" in types
    assert "same_finding" in types
    assert "same_asset" in types
    assert "related_service" in types
    assert "related_dns" in types
    assert "related_tls" in types
    assert "related_http" in types


def test_scan_result_becomes_correlated_service_context():
    scan = evidence(
        "scan_result",
        "Reconix scan returned",
        scan_id="scan-1",
        target="example.com",
        ports=[{"port": 80, "state": "open"}, {"port": 443, "state": "open"}],
        dns={"records": ["example.com"]},
        http={"status": 200},
        tls={"certificate": "present"},
        subdomains=["www.example.com"],
        cloud={"provider": "example-cloud"},
    )
    context = context_with(evidence("finding_observation", "finding", hostname="example.com"), scan)
    graph = build_graph(context)
    result = EvidenceCorrelator().correlate(context, graph)
    types = {item.type for item in context.evidence}

    assert {"reconix_port_observation", "reconix_dns_observation", "reconix_http_observation", "reconix_tls_observation", "reconix_subdomain_observation", "reconix_cloud_observation"} <= types
    assert any(relation.relationship_type == "related_service" for relation in result.relationships)


def test_duplicate_finding_does_not_inflate_hypothesis_confidence():
    primary = evidence("finding_observation", "finding", finding_id="finding-1", hostname="example.com")
    duplicate = evidence("scan_result", "same finding from scan", finding_id="finding-1", hostname="example.com")
    duplicate_context = context_with(primary, duplicate)
    duplicate_result = EvidenceCorrelator().correlate(duplicate_context, build_graph(duplicate_context))
    duplicate_hypothesis = HypothesisEngine().generate(duplicate_context, build_graph(duplicate_context), duplicate_result)[0]

    single_context = context_with(primary.model_copy())
    single_result = EvidenceCorrelator().correlate(single_context, build_graph(single_context))
    single_hypothesis = HypothesisEngine().generate(single_context, build_graph(single_context), single_result)[0]

    assert duplicate_result.duplicate_evidence_ids == [duplicate.id]
    assert duplicate_result.correlated_evidence_count == 1
    assert duplicate_hypothesis.confidence == single_hypothesis.confidence


def test_contradictory_evidence_reduces_confidence_and_remains_explicit():
    context = context_with(
        evidence("finding_observation", "finding", hostname="example.com"),
        evidence("observation", "expected exposure is false", hostname="example.com", contradicts=["H-001"]),
    )
    graph = build_graph(context)
    correlation = EvidenceCorrelator().correlate(context, graph)
    hypothesis = HypothesisEngine().generate(context, graph, correlation)[0]

    assert hypothesis.contradicting_evidence == ["E-observation-expected exposure is false"]
    assert hypothesis.confidence < 0.4


def test_confidence_is_clamped_and_missing_evidence_stays_explicit():
    items = [evidence("observation", f"observation-{index}", hostname="example.com", supports=["H-001"]) for index in range(30)]
    context = context_with(*items)
    graph = build_graph(context)
    correlation = EvidenceCorrelator().correlate(context, graph)
    hypotheses = HypothesisEngine().generate(context, graph, correlation)
    missing = MissingEvidenceAnalyzer().analyze(context, graph, hypotheses)
    evaluation = EvidenceEvaluator().evaluate(context, hypotheses)

    assert all(0.0 <= hypothesis.confidence <= 1.0 for hypothesis in hypotheses)
    assert any(item.description == "Historical alerts for this asset" for item in missing)
    assert "Historical access activity" in evaluation.missing_evidence


def test_report_exposes_relationships_and_correlated_count():
    context = context_with(
        evidence("finding_observation", "finding", hostname="example.com"),
        evidence("port_observation", "port 80", hostname="example.com", port=80),
        evidence("port_observation", "port 443", hostname="example.com", port=443),
    )
    graph = build_graph(context)
    correlation = EvidenceCorrelator().correlate(context, graph)
    hypotheses = HypothesisEngine().generate(context, graph, correlation)
    evaluation = EvidenceEvaluator().evaluate(context, hypotheses)
    report = ReportGenerator().generate(context, graph, hypotheses, evaluation, correlation=correlation)

    assert report.evidence_relationships
    assert report.correlated_evidence_count == len(correlation.unique_evidence_ids)
    assert report.hypotheses[0].contextual_evidence
