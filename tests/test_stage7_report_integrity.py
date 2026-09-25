from __future__ import annotations

import pytest

from app.engine.context import ContextBuilder
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.report import ReportGenerator
from app.engine.report_validation import ReportIntegrityError, validate_report_integrity
from app.models import (
    AssessmentConsistency,
    AssessmentConsistencyStatus,
    FinalAssessment,
)
from app.repository import PersistedInvestigation, SQLiteInvestigationRepository, utc_now
from app.service import InvestigationService
from app.config import Settings
from app.tools.registry import ToolRegistry
from tests.test_stage1 import request
from tests.test_stage2 import FakeThreatLens
from tests.test_stage5 import UnavailableReasoner


def report_inputs():
    context = ContextBuilder().build(request(), "INV-stage7")
    graph = build_graph(context)
    hypotheses = HypothesisEngine().generate(context, graph)
    evaluation = EvidenceEvaluator().evaluate(context, hypotheses)
    evaluation.missing_evidence = list(hypotheses[0].missing_evidence)
    return context, graph, hypotheses, evaluation


def assessment(classification: str, severity: str, confidence: float, source: str = "deterministic") -> FinalAssessment:
    return FinalAssessment(
        classification=classification,
        severity=severity,
        confidence=confidence,
        rationale="Validated final assessment rationale.",
        source=source,
    )


def generate(final: FinalAssessment, deterministic: FinalAssessment | None = None, **kwargs):
    context, graph, hypotheses, evaluation = report_inputs()
    consistency = kwargs.pop(
        "assessment_consistency", AssessmentConsistency(status="consistent", reason="Validated for test.")
    )
    return ReportGenerator().generate(
        context,
        graph,
        hypotheses,
        evaluation,
        deterministic_assessment=deterministic or final,
        final_assessment=final,
        assessment_consistency=consistency,
        **kwargs,
    )


def test_final_summary_uses_needs_investigation_assessment_not_stale_wording():
    report = generate(assessment("needs_investigation", "informational", 0.04))

    assert report.summary.startswith("Final assessment: needs_investigation (informational, confidence 0.04).")
    assert "benign" not in report.summary
    assert "confirmed" not in report.summary
    assert "confidence 1.00" not in report.summary


@pytest.mark.parametrize(
    ("classification", "severity", "confidence"),
    [("confirmed", "high", 0.90), ("benign", "low", 0.80)],
)
def test_final_summary_preserves_each_authoritative_final_assessment(classification, severity, confidence):
    report = generate(assessment(classification, severity, confidence, "reconciled"))

    assert report.summary.startswith(
        f"Final assessment: {classification} ({severity}, confidence {confidence:.2f})."
    )


def test_final_summary_distinguishes_deterministic_llm_and_final_confidence():
    deterministic = assessment("needs_investigation", "informational", 0.04)
    final = assessment("needs_investigation", "informational", 0.50, "llm")
    context, graph, hypotheses, evaluation = report_inputs()
    evidence_id = context.evidence[0].id
    llm = {
        "classification": "needs_investigation",
        "severity": "informational",
        "confidence": 0.50,
        "summary": "Evidence requires review.",
        "summary_evidence_refs": [evidence_id],
        "human_review_required": True,
        "automated_action": "none",
    }
    report = ReportGenerator().generate(
        context, graph, hypotheses, evaluation,
        llm_assessment=llm,
        deterministic_assessment=deterministic,
        final_assessment=final,
        assessment_consistency=AssessmentConsistency(status="consistent", reason="Validated LLM interpretation."),
    )

    assert report.deterministic_assessment.confidence == 0.04
    assert report.llm_assessment["confidence"] == 0.50
    assert report.final_assessment.confidence == 0.50
    assert "confidence 0.50" in report.summary
    assert "confidence 0.04" not in report.summary


def test_final_summary_uses_supplied_final_confidence_not_llm_or_hypothesis_confidence():
    deterministic = assessment("needs_investigation", "informational", 0.04)
    context, graph, hypotheses, evaluation = report_inputs()
    evidence_id = context.evidence[0].id
    llm = {
        "classification": "needs_investigation",
        "severity": "informational",
        "confidence": 0.35,
        "summary": "Evidence requires review.",
        "summary_evidence_refs": [evidence_id],
        "hypotheses": [{
            "id": hypotheses[0].id,
            "statement": "The observed service requires review.",
            "evidence_refs": [evidence_id],
            "confidence": 0.35,
            "status": "partially_supported",
        }],
        "human_review_required": True,
        "automated_action": "none",
    }
    report = ReportGenerator().generate(
        context, graph, hypotheses, evaluation,
        llm_assessment=llm,
        deterministic_assessment=deterministic,
        final_assessment=deterministic,
        assessment_consistency=AssessmentConsistency(status="reconciled", reason="Deterministic final retained."),
    )

    assert report.deterministic_assessment.confidence == 0.04
    assert report.llm_assessment["confidence"] == 0.35
    assert report.llm_assessment["hypotheses"][0]["confidence"] == 0.35
    assert report.final_assessment.confidence == 0.04
    assert report.summary.startswith("Final assessment: needs_investigation (informational, confidence 0.04).")
    assert "confidence 0.35" not in report.summary


def test_invalid_consistency_is_only_allowed_as_deterministic_fallback():
    deterministic = assessment("needs_investigation", "informational", 0.04)
    report = generate(
        deterministic,
        deterministic,
        assessment_consistency=AssessmentConsistency(
            status=AssessmentConsistencyStatus.invalid,
            reason="Consistency validation failed; deterministic fallback retained.",
        ),
    )
    assert report.final_assessment == report.deterministic_assessment

    unsafe = report.model_copy(update={
        "final_assessment": assessment("benign", "low", 0.8),
        "summary": "Final assessment: benign (low, confidence 0.80).",
    })
    with pytest.raises(ReportIntegrityError, match="deterministic fallback"):
        validate_report_integrity(unsafe)


def test_summary_and_invalid_evidence_references_are_rejected():
    report = generate(assessment("needs_investigation", "informational", 0.04))
    stale_summary = report.model_copy(update={"summary": "Final assessment: benign (low, confidence 1.00)."})
    with pytest.raises(ReportIntegrityError, match="summary"):
        validate_report_integrity(stale_summary)

    stale_tail = report.model_copy(update={
        "summary": report.summary + " Final result benign with confidence 1.00.",
    })
    with pytest.raises(ReportIntegrityError, match="contradictory classification"):
        validate_report_integrity(stale_tail)

    invalid_evidence = report.model_copy(update={
        "hypotheses": [report.hypotheses[0].model_copy(update={"supporting_evidence": ["E-unknown"]})]
    })
    with pytest.raises(ReportIntegrityError, match="unknown evidence"):
        validate_report_integrity(invalid_evidence)


def test_llm_validation_fallback_and_persisted_report_remain_usable(tmp_path):
    service = InvestigationService(
        settings=Settings(database_path=str(tmp_path / "orion.db")),
        registry=ToolRegistry(tools=[FakeThreatLens()]),
        llm_reasoner=UnavailableReasoner(),
    )
    report = service.investigate(request())
    assert report.llm_assessment is None
    assert report.final_assessment == report.deterministic_assessment
    assert report.summary.startswith("Final assessment: needs_investigation")

    loaded = SQLiteInvestigationRepository(str(tmp_path / "orion.db")).get(report.investigation_id)
    assert loaded is not None and loaded.report == report


def test_repository_keeps_legacy_deterministic_fields_without_rewriting_history(tmp_path):
    """Stage 5/6 top-level fields are deterministic; nested final is authoritative."""
    deterministic = assessment("needs_investigation", "informational", 0.04).model_copy(update={
        "rationale": "Deterministic investigation evidence is insufficient to establish a confirmed security condition.",
    })
    final = assessment("needs_investigation", "informational", 0.35, "llm").model_copy(update={
        "rationale": "Evidence requires review.",
    })
    context, graph, hypotheses, evaluation = report_inputs()
    context.primary_alert.finding.severity = "informational"
    evaluation.confidence = 0.04
    evidence_id = context.evidence[0].id
    llm = {
        "classification": "needs_investigation",
        "severity": "informational",
        "confidence": 0.35,
        "summary": "Evidence requires review.",
        "summary_evidence_refs": [evidence_id],
        "human_review_required": True,
        "automated_action": "none",
    }
    generated = ReportGenerator().generate(
        context, graph, hypotheses, evaluation,
        llm_assessment=llm,
        deterministic_assessment=deterministic,
        final_assessment=final,
        assessment_consistency=AssessmentConsistency(
            status="consistent",
            reason="The validated LLM assessment is supported by the relevant investigation evidence.",
        ),
    )
    # Older records include a deterministic observation after the canonical
    # final sentence. It is safe and must remain byte-for-byte report content.
    historical = generated.model_copy(update={
        "summary": generated.summary + " The scan confirms an externally reachable web service.",
    })
    repository = SQLiteInvestigationRepository(str(tmp_path / "orion.db"))
    now = utc_now()
    repository.save(PersistedInvestigation(
        investigation_id=historical.investigation_id,
        alert_id=historical.alert_id,
        status="completed",
        started_at=now,
        completed_at=now,
        stop_reason="completed",
        error=None,
        timeout=False,
        created_at=now,
        updated_at=now,
        report=historical,
    ))

    loaded = repository.get(historical.investigation_id)
    assert loaded is not None and loaded.report is not None
    assert loaded.report.confidence == 0.04  # legacy deterministic field
    assert loaded.report.llm_assessment["confidence"] == 0.35
    assert loaded.report.final_assessment.confidence == 0.35
    assert loaded.report.summary == historical.summary  # no historical rewrite
