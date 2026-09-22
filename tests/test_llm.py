from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.llm.base import LLMError, LLMReasoner
from app.llm.gemini import GeminiReasoner
from app.llm.schemas import AnalystAssessment, validate_assessment
from app.models import Evidence
from app.service import InvestigationService
from app.tools.registry import ToolRegistry
from tests.test_stage1 import ALERT, request
from tests.test_stage2 import FakeThreatLens


def assessment(evidence_id: str, hypothesis_id: str) -> AnalystAssessment:
    return AnalystAssessment(
        classification="needs_investigation", severity="low", confidence=0.4,
        summary="Evidence requires human review.", summary_evidence_refs=[evidence_id],
        hypotheses=[{"id": hypothesis_id, "statement": "Observed service requires validation.", "evidence_refs": [evidence_id], "confidence": 0.4, "supporting_evidence": [evidence_id], "status": "unresolved"}],
        supporting_evidence=[evidence_id], human_review_required=True, automated_action="none",
    )


class FakeTypes:
    class GenerateContentConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs


class FakeGeminiClient:
    def __init__(self, response=None, error: Exception | None = None):
        self.models = self
        self.response = response
        self.error = error
        self.called = None

    def generate_content(self, **kwargs):
        self.called = kwargs
        if self.error:
            raise self.error
        return self.response


class FakeReasoner(LLMReasoner):
    def __init__(self, invalid: bool = False, failure: bool = False):
        self.invalid = invalid
        self.failure = failure

    def analyze(self, alert, evidence, hypotheses, missing_evidence, tool_activity):
        if self.failure:
            raise LLMError("llm_timeout")
        return assessment("unknown" if self.invalid else evidence[0].id, hypotheses[0].id)


def test_gemini_provider_uses_structured_response_and_configured_model():
    response = type("Response", (), {"parsed": assessment("E-1", "H-001").model_dump()})()
    client = FakeGeminiClient(response)
    reasoner = GeminiReasoner(Settings(gemini_api_key="AQ.test", gemini_model="test-model"), client, FakeTypes)
    result = reasoner.analyze(request(), [Evidence(id="E-1", source="test", type="observation", finding="x", confidence=1, raw_reference="x")], [], [], [])
    assert result.automated_action == "none"
    assert client.called["model"] == "test-model"
    assert client.called["config"].kwargs["response_schema"] is AnalystAssessment


def test_gemini_missing_key_invalid_json_timeout_and_api_failure_are_safe():
    reasoner = GeminiReasoner(Settings())
    with pytest.raises(LLMError):
        reasoner.analyze(request(), [], [], [], [])
    invalid = GeminiReasoner(Settings(gemini_api_key="AQ.test"), FakeGeminiClient(type("Response", (), {"parsed": None, "text": "not json"})()), FakeTypes)
    timeout = GeminiReasoner(Settings(gemini_api_key="AQ.test"), FakeGeminiClient(error=TimeoutError()), FakeTypes)
    for reasoner in (invalid, timeout):
        with pytest.raises(LLMError):
            reasoner.analyze(request(), [], [], [], [])


def test_assessment_schema_rejects_invalid_confidence_and_automated_action():
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({"classification": "needs_investigation", "severity": "low", "confidence": 2, "summary": "x", "human_review_required": True, "automated_action": "remediate"})


def test_successful_llm_assessment_is_reported_without_new_evidence():
    service = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=FakeReasoner())
    report = service.investigate(request())
    assert report.state.status == "completed"
    assert report.llm_status == "success"
    assert report.llm_assessment["automated_action"] == "none"
    assert set(report.llm_assessment["supporting_evidence"]) <= {item.id for item in report.evidence}
    assert len(report.evidence) == report.state.evidence_count


def test_invalid_llm_evidence_or_failure_preserves_deterministic_report_as_partial():
    for reasoner in (FakeReasoner(invalid=True), FakeReasoner(failure=True)):
        report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=reasoner).investigate(request())
        assert report.state.status == "partial"
        assert report.stop_reason in {"llm_timeout", "llm_validation_failed"}
        assert report.llm_assessment is None
        assert report.automated_action == "none"


def test_unknown_evidence_hypothesis_and_missing_review_are_rejected():
    valid = assessment("E-1", "H-001")
    with pytest.raises(ValueError):
        validate_assessment(valid.model_copy(update={"supporting_evidence": ["unknown"]}), {"E-1"}, {"H-001"}, [])
    with pytest.raises(ValueError):
        validate_assessment(valid.model_copy(update={"hypotheses": [valid.hypotheses[0].model_copy(update={"id": "H-999"})]}), {"E-1"}, {"H-001"}, [])
    with pytest.raises(ValueError):
        validate_assessment(valid.model_copy(update={"human_review_required": False}), {"E-1"}, {"H-001"}, ["Historical access activity"])


def test_factual_claims_require_evidence_references():
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({
            "classification": "needs_investigation", "severity": "low", "confidence": 0.4,
            "summary": "Observed service.", "summary_evidence_refs": ["E-1"],
            "factual_claims": [{"text": "Invented fact", "evidence_refs": []}],
            "human_review_required": True, "automated_action": "none",
        })


class ProviderError(Exception):
    def __init__(self, status_code):
        self.status_code = status_code


def test_gemini_status_codes_are_safely_classified():
    for status, code in ((503, "llm_unavailable"), (429, "llm_quota_exhausted")):
        reasoner = GeminiReasoner(Settings(gemini_api_key="AQ.test"), FakeGeminiClient(error=ProviderError(status)), FakeTypes)
        with pytest.raises(LLMError) as error:
            reasoner.analyze(request(), [], [], [], [])
        assert error.value.code == code
