from __future__ import annotations

import pytest

from app.config import Settings
from app.engine.context import ContextBuilder
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.report import ReportGenerator
from app.llm.base import LLMError, LLMReasoner
from app.llm.schemas import AnalystAssessment, AnalystClaim, validate_assessment
from app.models import Evaluation
from app.service import InvestigationService
from app.tools.registry import ToolRegistry
from tests.test_stage1 import request
from tests.test_stage2 import FakeThreatLens


class AssessmentReasoner(LLMReasoner):
    provider = "gemini"
    model = "gemini-3.5-flash-lite"
    fallback_used = False
    primary_failure_reason = None

    def analyze(self, alert, evidence, hypotheses, missing_evidence, tool_activity):
        evidence_id = evidence[0].id
        hypothesis_id = hypotheses[0].id
        return AnalystAssessment(
            classification="confirmed",
            severity="high",
            confidence=0.9,
            summary="Verified evidence identifies an externally reachable service.",
            summary_evidence_refs=[evidence_id],
            factual_claims=[{
                "text": "An externally reachable service was observed.",
                "evidence_refs": [evidence_id],
            }],
            hypotheses=[{
                "id": hypothesis_id,
                "statement": "The observed service requires security-context validation.",
                "evidence_refs": [evidence_id],
                "confidence": 0.9,
                "supporting_evidence": [evidence_id],
                "status": "partially_supported",
            }],
            unresolved_questions=["Is the service intentionally exposed?"],
            recommended_next_steps=[],
            human_review_required=True,
            automated_action="none",
        )


class UnavailableReasoner(LLMReasoner):
    provider = "gemini"
    model = "gemini-3.5-flash-lite"
    fallback_used = False
    primary_failure_reason = None

    def analyze(self, *args):
        raise LLMError("llm_unavailable", transient=True)


def service(reasoner: LLMReasoner) -> InvestigationService:
    return InvestigationService(
        settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=reasoner
    )


def test_successful_gemini_assessment_is_preserved_but_final_is_reconciled():
    report = service(AssessmentReasoner()).investigate(request())

    assert report.llm_status == "success"
    assert report.llm_provider == "gemini"
    assert report.llm_model == "gemini-3.5-flash-lite"
    assert report.llm_assessment is not None
    assert report.llm_assessment["summary"] == "Verified evidence identifies an externally reachable service."
    assert report.llm_assessment["factual_claims"][0]["evidence_refs"]
    assert report.deterministic_assessment.classification == "needs_investigation"
    assert report.final_assessment.classification == "needs_investigation"
    assert report.final_assessment.source == "reconciled"
    assert report.summary.startswith("Final assessment: needs_investigation")


def test_llm_unavailability_preserves_a_usable_deterministic_report():
    report = service(UnavailableReasoner()).investigate(request())

    assert report.llm_status == "failed"
    assert report.llm_failure_reason == "llm_unavailable"
    assert report.llm_assessment is None
    assert report.final_assessment == report.deterministic_assessment
    assert report.summary.startswith("Final assessment: needs_investigation")
    assert report.automated_action == "none"


def test_evidence_linked_factual_claim_is_accepted_against_investigation_evidence():
    assessment = AnalystAssessment(
        classification="needs_investigation", severity="low", confidence=0.4,
        summary="The supplied evidence requires review.", summary_evidence_refs=["E-1"],
        factual_claims=[{"text": "An observation was supplied.", "evidence_refs": ["E-1"]}],
        human_review_required=True, automated_action="none",
    )

    assert validate_assessment(assessment, {"E-1"}, set(), []) == assessment


def test_invalid_evidence_reference_is_rejected_before_report_rendering():
    context = ContextBuilder().build(request(), "INV-stage5")
    graph = build_graph(context)
    hypotheses = HypothesisEngine().generate(context, graph)
    evaluation = EvidenceEvaluator().evaluate(context, hypotheses)
    invalid = AssessmentReasoner().analyze(None, context.evidence, hypotheses, evaluation.missing_evidence, [])
    invalid = invalid.model_copy(update={
        "factual_claims": [AnalystClaim(text="Unknown claim.", evidence_refs=["E-unknown"])]
    })

    with pytest.raises(ValueError, match="unknown evidence"):
        ReportGenerator().generate(context, graph, hypotheses, evaluation, llm_assessment=invalid.model_dump())


def test_missing_evidence_has_deterministic_investigation_steps():
    report = service(UnavailableReasoner()).investigate(request())

    assert "Expected exposure status" in report.missing_evidence
    assert "Verify whether the service is intentionally exposed." in report.investigation_steps


def test_missing_security_context_cannot_silently_remove_human_review():
    context = ContextBuilder().build(request(), "INV-stage5-review")
    graph = build_graph(context)
    hypotheses = HypothesisEngine().generate(context, graph)
    evaluation = Evaluation(
        classification="needs_investigation",
        confidence=0.3,
        missing_evidence=["Authentication and access-control configuration"],
        needs_investigation=False,
    )

    report = ReportGenerator().generate(context, graph, hypotheses, evaluation)

    assert report.human_review_required
    assessment = AssessmentReasoner().analyze(None, context.evidence, hypotheses, evaluation.missing_evidence, [])
    assert assessment.human_review_required
    with pytest.raises(ValueError, match="removed required human review"):
        validate_assessment(
            assessment.model_copy(update={"human_review_required": False}),
            {item.id for item in context.evidence},
            {item.id for item in hypotheses},
            evaluation.missing_evidence,
        )
