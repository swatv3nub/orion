from __future__ import annotations

import json

import pytest

from app.config import Settings
from app.llm.base import LLMError, LLMReasoner
from app.llm.factory import FallbackReasoner
from app.llm.groq import GroqReasoner
from app.llm.openrouter import OpenRouterReasoner
from app.llm.schemas import AnalystAssessment, validate_assessment
from app.models import Evidence
from app.service import InvestigationService
from app.tools.registry import ToolRegistry
from tests.test_stage1 import request
from tests.test_stage2 import FakeThreatLens


def assessment(evidence_id: str = "E-1", hypothesis_id: str = "H-001") -> AnalystAssessment:
    return AnalystAssessment(
        classification="needs_investigation", severity="low", confidence=0.4,
        summary="Evidence requires human review.", summary_evidence_refs=[evidence_id],
        hypotheses=[{"id": hypothesis_id, "statement": "Observed service requires validation.", "evidence_refs": [evidence_id], "confidence": 0.4, "supporting_evidence": [evidence_id], "status": "unresolved"}],
        supporting_evidence=[evidence_id], human_review_required=True, automated_action="none",
    )


class FakeClient:
    def __init__(self, response=None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.called = None
        self.chat = type("Chat", (), {"completions": self})()

    def create(self, **kwargs):
        self.called = kwargs
        if self.error:
            raise self.error
        return self.response


def response(value: AnalystAssessment):
    message = type("Message", (), {"content": json.dumps(value.model_dump())})()
    return type("Response", (), {"choices": [type("Choice", (), {"message": message})()]})()


class ProviderError(Exception):
    def __init__(self, status_code: int):
        self.status_code = status_code


class FakeReasoner(LLMReasoner):
    def __init__(self, provider: str, model: str, outcomes: list[AnalystAssessment | Exception]):
        self.provider, self.model, self.outcomes = provider, model, outcomes
        self.calls = 0

    def analyze(self, *args):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return outcome(*args)
        return outcome


def test_groq_and_openrouter_return_the_same_structured_assessment():
    for reasoner in (
        GroqReasoner(Settings(groq_api_key="test"), FakeClient(response(assessment()))),
        OpenRouterReasoner(Settings(openrouter_api_key="test", openrouter_model="configured"), FakeClient(response(assessment()))),
    ):
        result = reasoner.analyze(request(), [Evidence(id="E-1", source="test", type="observation", finding="x", confidence=1, raw_reference="x")], [], [], [])
        assert result.automated_action == "none"
        assert reasoner.client.called["response_format"]["json_schema"]["strict"]


@pytest.mark.parametrize("status, code", [(429, "llm_quota_exhausted"), (503, "llm_unavailable")])
def test_groq_http_errors_are_classified(status, code):
    reasoner = GroqReasoner(Settings(groq_api_key="test"), FakeClient(error=ProviderError(status)))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == code and error.value.transient


@pytest.mark.parametrize("error", [ProviderError(429), ProviderError(503), TimeoutError()])
def test_transient_groq_failure_retries_once_then_falls_back(error):
    primary = FakeReasoner("groq", "primary", [LLMError("llm_quota_exhausted", transient=True) if isinstance(error, ProviderError) and error.status_code == 429 else LLMError("llm_unavailable" if isinstance(error, ProviderError) else "llm_timeout", transient=True), LLMError("llm_unavailable", transient=True)])
    fallback = FakeReasoner("openrouter", "fallback", [assessment()])
    reasoner = FallbackReasoner(primary, fallback)
    assert reasoner.analyze(None, [], [], [], []).automated_action == "none"
    assert primary.calls == 2
    assert fallback.calls == 1
    assert reasoner.fallback_used and reasoner.provider == "openrouter"


def test_invalid_output_and_validation_failures_do_not_fallback():
    primary = FakeReasoner("groq", "primary", [LLMError("llm_invalid_output")])
    fallback = FakeReasoner("openrouter", "fallback", [assessment()])
    with pytest.raises(LLMError):
        FallbackReasoner(primary, fallback).analyze(None, [], [], [], [])
    assert fallback.calls == 0
    invalid = assessment("unknown")
    with pytest.raises(ValueError):
        validate_assessment(invalid, {"E-1"}, {"H-001"}, [])


def test_validation_failure_does_not_invoke_fallback_provider():
    primary = FakeReasoner("groq", "primary", [assessment("unknown")])
    fallback = FakeReasoner("openrouter", "fallback", [assessment()])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=FallbackReasoner(primary, fallback)).investigate(request())
    assert report.llm_failure_reason == "llm_validation_failed"
    assert fallback.calls == 0


def test_unknown_hypothesis_missing_review_and_automated_action_are_rejected():
    valid = assessment()
    with pytest.raises(ValueError):
        validate_assessment(valid.model_copy(update={"hypotheses": [valid.hypotheses[0].model_copy(update={"id": "H-999"})]}), {"E-1"}, {"H-001"}, [])
    with pytest.raises(ValueError):
        validate_assessment(valid.model_copy(update={"human_review_required": False}), {"E-1"}, {"H-001"}, ["Historical access activity"])
    assert AnalystAssessment.model_validate({**valid.model_dump(), "automated_action": "none"}).automated_action == "none"


def test_both_provider_failures_preserve_deterministic_report():
    primary = FakeReasoner("groq", "primary", [LLMError("llm_unavailable", transient=True), LLMError("llm_unavailable", transient=True)])
    fallback = FakeReasoner("openrouter", "fallback", [LLMError("llm_unavailable", transient=True)])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=FallbackReasoner(primary, fallback)).investigate(request())
    assert report.state.status == "partial"
    assert report.llm_assessment is None
    assert report.llm_provider == "openrouter"
    assert report.llm_fallback_used
    assert report.llm_primary_failure_reason == "llm_unavailable"
    assert report.automated_action == "none"


def test_successful_provider_metadata_and_validation_failure_are_reported():
    success = FakeReasoner("groq", "openai/gpt-oss-120b", [lambda alert, evidence, hypotheses, missing, activity: assessment(evidence[0].id, hypotheses[0].id)])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=success).investigate(request())
    assert report.llm_status == "success"
    assert report.llm_provider == "groq"
    assert report.llm_model == "openai/gpt-oss-120b"
    invalid = FakeReasoner("groq", "primary", [assessment("unknown")])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=invalid).investigate(request())
    assert report.llm_failure_reason == "llm_validation_failed"
