from app.engine.context import ContextBuilder
from app.engine.correlator import EvidenceCorrelator
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.report import ReportGenerator
from app.models import Evidence, InvestigationContext, InvestigationRequest

from tests.test_stage1 import ALERT


def scan(findings):
    return Evidence(id="E-scan", source="reconix_cloud", type="scan_result", finding="scan returned", confidence=1, raw_reference="scan-1", metadata={"scan_id": "scan-1", "findings": findings})


def context(*items):
    request = InvestigationRequest.model_validate(ALERT)
    return InvestigationContext(investigation_id="INV-stage4", primary_alert=request, asset=request.asset, evidence=list(items))


def normalize(*findings):
    value = context(scan(list(findings)))
    graph = build_graph(value)
    return value, EvidenceCorrelator().correlate(value, graph), graph


def finding(kind, evidence, **extra):
    return {"type": kind, "evidence": evidence, "metadata": {"category": kind}, **extra}


def test_normalizes_only_atomic_reconix_observations():
    value, _, _ = normalize(
        finding("port", {"port": 80, "hostname": "example.com", "source": "reconix", "severity": "info"}),
        finding("dns", {"record": "104.20.23.154", "hostname": "example.com"}),
        finding("ssl", {"san": "*.example.com", "hostname": "example.com"}),
        finding("http", {"url": "https://example.com", "status": 200}),
        finding("subdomain", {"subdomain": "www.example.com"}),
        finding("whois", {"hostname": "example.com", "field": "Registrar", "value": "Example Registrar"}),
    )
    types = {item.type for item in value.evidence}
    assert {"reconix_port_observation", "reconix_dns_observation", "reconix_tls_observation", "reconix_http_observation", "reconix_subdomain_observation", "reconix_whois_observation"} <= types
    assert len(value.evidence) == 7  # One raw scan provenance record plus six atomic facts.
    assert all("source observed" not in item.finding and "metadata observed" not in item.finding for item in value.evidence)


def test_cloud_with_url_stays_cloud_and_is_meaningful():
    value, _, _ = normalize(finding("cloud", {"url": "https://example.s3.amazonaws.com", "status": 403}))
    cloud = next(item for item in value.evidence if item.type.startswith("reconix_"))
    assert cloud.type == "reconix_cloud_observation"
    assert "HTTP 403" in cloud.finding


def test_semantic_relationships_are_specific_not_same_scan_noise():
    value, result, _ = normalize(
        finding("port", {"port": 80, "hostname": "example.com"}),
        finding("port", {"port": 443, "hostname": "example.com"}),
        finding("http", {"url": "https://example.com", "status": 200}),
        finding("dns", {"hostname": "example.com", "record": "104.20.23.154"}),
        finding("ssl", {"hostname": "example.com", "san": "*.example.com"}),
    )
    types = {item.relationship_type for item in result.relationships}
    assert {"related_service", "related_http", "related_dns", "related_tls"} <= types
    assert "same_scan" not in types
    assert result.semantic_relationship_count == len(result.relationships)


def test_duplicate_cross_source_port_is_corroboration_not_extra_confidence():
    original = Evidence(id="E-alert", source="threatlens", type="finding_observation", finding="example.com has port 80 open", confidence=1, raw_reference="alert", metadata={"observation_type": "port", "hostname": "example.com", "port": 80})
    value, result, graph = normalize(finding("port", {"hostname": "example.com", "port": 80}))
    value.evidence.insert(0, original)
    result = EvidenceCorrelator().correlate(value, graph)
    hypotheses = HypothesisEngine().generate(value, graph, result)
    assert any(item.relationship_type == "corroborates" for item in result.relationships)
    assert result.canonical_evidence_count == 1
    assert len(hypotheses[0].supporting_evidence) == 1


def test_hypothesis_refines_service_and_keeps_missing_evidence_explicit():
    value, result, graph = normalize(
        finding("port", {"port": 80, "hostname": "example.com"}),
        finding("port", {"port": 443, "hostname": "example.com"}),
        finding("http", {"url": "https://example.com", "status": 200}),
        finding("dns", {"hostname": "example.com", "record": "104.20.23.154"}),
        finding("ssl", {"hostname": "example.com", "san": "*.example.com"}),
    )
    hypothesis = HypothesisEngine().generate(value, graph, result)[0]
    assert hypothesis.title == "Internet-facing web service requires validation"
    assert len(hypothesis.supporting_evidence) == 3
    assert len(hypothesis.contextual_evidence) == 2
    assert "Historical access activity" in hypothesis.missing_evidence
    assert 0 < hypothesis.confidence < 0.7


def test_contradiction_lowers_bounded_confidence():
    value, result, graph = normalize(finding("port", {"port": 80, "hostname": "example.com"}))
    contradiction = Evidence(id="E-no", source="inventory", type="port_observation", finding="port 80 is not expected", confidence=1, raw_reference="inventory", metadata={"observation_type": "port", "hostname": "example.com", "port": 81, "contradicts": ["H-001"]})
    value.evidence.append(contradiction)
    result = EvidenceCorrelator().correlate(value, graph)
    hypothesis = HypothesisEngine().generate(value, graph, result)[0]
    assert contradiction.id in hypothesis.contradicting_evidence
    assert 0 <= hypothesis.confidence <= 1


def test_report_counters_relationships_and_steps_are_exposed():
    value, result, graph = normalize(finding("port", {"port": 80, "hostname": "example.com"}), finding("http", {"url": "https://example.com", "status": 200}))
    hypotheses = HypothesisEngine().generate(value, graph, result)
    evaluation = EvidenceEvaluator().evaluate(value, hypotheses)
    evaluation.missing_evidence = hypotheses[0].missing_evidence
    report = ReportGenerator().generate(value, graph, hypotheses, evaluation, correlation=result)
    assert report.raw_evidence_count > report.canonical_evidence_count
    assert report.evidence_relationships
    assert report.semantic_relationship_count
    assert "Verify whether the service is intentionally exposed." in report.investigation_steps


def test_whois_facts_have_distinct_canonical_identity():
    value, result, _ = normalize(
        finding("whois", {"hostname": "example.com", "field": "Domain Name", "value": "EXAMPLE.COM"}),
        finding("whois", {"hostname": "example.com", "field": "Creation Date", "value": "1995-08-14"}),
        finding("whois", {"hostname": "example.com", "field": "Registrar", "value": "Example Registrar"}),
    )
    whois = [item for item in value.evidence if item.type == "reconix_whois_observation"]
    assert len({item.canonical_evidence_id for item in whois}) == 3
    assert result.canonical_evidence_count == 3


def test_dns_facts_are_distinct_and_no_same_source_relationship_is_emitted():
    value, result, _ = normalize(
        finding("dns", {"hostname": "example.com", "record": "172.66.147.243"}),
        finding("dns", {"hostname": "example.com", "record": "104.20.23.154"}),
    )
    dns = [item for item in value.evidence if item.type == "reconix_dns_observation"]
    assert len({item.canonical_evidence_id for item in dns}) == 2
    assert not any(item.relationship_type == "same_source" for item in result.relationships)


def test_relationships_use_one_strongest_semantic_link_per_pair():
    _, result, _ = normalize(
        finding("dns", {"hostname": "example.com", "record": "104.20.23.154"}),
        finding("port", {"hostname": "example.com", "port": 80}),
    )
    pair_types = [item.relationship_type for item in result.relationships]
    assert pair_types == ["related_dns"]


def test_cloud_provider_does_not_create_a_clique_but_family_does():
    _, provider_result, _ = normalize(
        finding("cloud", {"url": "https://storage.googleapis.com/example", "status": 403}),
        finding("cloud", {"url": "https://storage.googleapis.com/example-dev", "status": 403}),
    )
    _, family_result, _ = normalize(
        finding("cloud", {"url": "https://example.s3.amazonaws.com", "status": 403}),
        finding("cloud", {"url": "https://example-dev.s3.amazonaws.com", "status": 403}),
    )
    assert not any(item.relationship_type == "related_cloud" for item in provider_result.relationships)
    assert [item.relationship_type for item in family_result.relationships] == ["related_cloud"]


def test_cloud_candidates_have_one_bounded_confidence_contribution():
    one, one_result, one_graph = normalize(finding("cloud", {"url": "https://one.s3.amazonaws.com", "status": 403}))
    many, many_result, many_graph = normalize(*[
        finding("cloud", {"url": f"https://candidate-{index}.s3.amazonaws.com", "status": 403})
        for index in range(14)
    ])
    one_hypothesis = HypothesisEngine().generate(one, one_graph, one_result)[0]
    many_hypothesis = HypothesisEngine().generate(many, many_graph, many_result)[0]
    assert one_hypothesis.confidence == many_hypothesis.confidence


def test_duplicate_scan_expansion_does_not_add_corroboration():
    original = Evidence(id="E-alert", source="threatlens", type="finding_observation", finding="example.com has port 80 open", confidence=1, raw_reference="alert", metadata={"observation_type": "port", "hostname": "example.com", "port": 80})
    raw_scan = scan([finding("port", {"hostname": "example.com", "port": 80})])
    value = context(original, raw_scan)
    result = EvidenceCorrelator().correlate(value, build_graph(value))
    assert len(result.unique_evidence_ids) == 1
    assert sum(item.relationship_type == "corroborates" for item in result.relationships) == 1
