from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.llm.base import LLMError, LLMReasoner, llm_input
from app.llm.factory import FallbackReasoner, create_reasoner
from app.llm.gemini import GeminiReasoner
from app.llm.openai import OpenAIReasoner
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
        self.calls = 0
        self.chat = type("Chat", (), {"completions": self})()

    def create(self, **kwargs):
        self.called = kwargs
        self.calls += 1
        if self.error:
            raise self.error
        return self.response


class FakeGeminiClient:
    def __init__(self, response=None, error: Exception | None = None):
        self.response = response
        self.error = error
        self.called = None
        self.calls = 0

    def post(self, url, **kwargs):
        self.called = {"url": url, **kwargs}
        self.calls += 1
        if self.error:
            raise self.error
        return self.response


def response(value: AnalystAssessment):
    return raw_response(json.dumps(value.model_dump()))


def raw_response(content, finish_reason=None):
    message = type("Message", (), {"content": content})()
    choice = type("Choice", (), {"message": message, "finish_reason": finish_reason})()
    return type("Response", (), {"choices": [choice]})()


def gemini_response(content, finish_reason="STOP"):
    return {"candidates": [{"finishReason": finish_reason, "content": {"parts": [{"text": content}]}}]}


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


def test_openai_and_openrouter_return_the_same_structured_assessment():
    for reasoner in (
        OpenAIReasoner(Settings(openai_api_key="test"), FakeClient(response(assessment()))),
        OpenRouterReasoner(Settings(openrouter_api_key="test", openrouter_model="configured"), FakeClient(response(assessment()))),
    ):
        result = reasoner.analyze(request(), [Evidence(id="E-1", source="test", type="observation", finding="x", confidence=1, raw_reference="x")], [], [], [])
        assert result.automated_action == "none"
        assert reasoner.client.called["response_format"]["json_schema"]["strict"]
        if reasoner.provider == "openai":
            assert reasoner.client.called["reasoning_effort"] == "low"
            assert reasoner.client.called["max_completion_tokens"] == Settings().llm_max_output_tokens
            assert "max_tokens" not in reasoner.client.called


def test_gemini_returns_structured_assessment():
    client = FakeGeminiClient(gemini_response(json.dumps(assessment().model_dump())))
    result = GeminiReasoner(Settings(gemini_api_key="test"), client).analyze(
        request(), [Evidence(id="E-1", source="test", type="observation", finding="x", confidence=1, raw_reference="x")], [], [], []
    )
    assert result.automated_action == "none"
    assert client.called["json"]["systemInstruction"]
    assert client.called["json"]["generationConfig"]["responseMimeType"] == "application/json"
    assert client.called["json"]["generationConfig"]["responseSchema"]["type"] == "OBJECT"
    assert client.called["url"].endswith(":generateContent")


@pytest.mark.parametrize("response", [
    {"candidates": []},
    {"candidates": [{"finishReason": "STOP"}]},
    {"candidates": [{"finishReason": "STOP", "content": {"parts": [{}]}}]},
])
def test_gemini_missing_candidate_content_or_text_fails_closed(response):
    with pytest.raises(LLMError) as error:
        GeminiReasoner(Settings(gemini_api_key="test"), FakeGeminiClient(response)).analyze(request(), [], [], [], [])
    assert error.value.code == "llm_invalid_output"


def test_gemini_empty_malformed_and_incomplete_output_fail_closed():
    for response in (gemini_response(""), gemini_response("{"), gemini_response("{}", "MAX_TOKENS")):
        with pytest.raises(LLMError) as error:
            GeminiReasoner(Settings(gemini_api_key="test"), FakeGeminiClient(response)).analyze(request(), [], [], [], [])
        assert error.value.code == "llm_invalid_output"


def test_gemini_provider_errors_are_transient_and_do_not_log_keys(caplog):
    secret = "gemini-secret"
    with pytest.raises(LLMError) as error:
        GeminiReasoner(Settings(gemini_api_key=secret), FakeGeminiClient(error=ProviderError(503))).analyze(request(), [], [], [], [])
    assert error.value.code == "llm_unavailable" and error.value.transient
    assert secret not in str(error.value)
    assert secret not in "\n".join(record.message for record in caplog.records)


def test_openrouter_accepts_compact_single_object_output():
    content = (
        '{"classification":"needs_investigation","severity":"low","confidence":0.4,'
        '"summary":"Observed service requires review.","summary_evidence_refs":["E-1"],'
        '"factual_claims":[],"hypotheses":[],"supporting_evidence":["E-1"],'
        '"contradicting_evidence":[],"unresolved_questions":[],"recommended_next_steps":[],'
        '"human_review_required":true,"automated_action":"none"}'
    )
    client = FakeClient(raw_response(content))
    result = OpenRouterReasoner(
        Settings(openrouter_api_key="test", openrouter_model="configured"), client
    ).analyze(
        request(), [Evidence(id="E-1", source="test", type="observation", finding="x", confidence=1, raw_reference="x")], [], [], []
    )
    assert result.summary == "Observed service requires review."
    assert client.called["response_format"]["json_schema"]["strict"]


def test_assessment_output_lengths_are_bounded():
    value = assessment().model_dump()
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({**value, "summary": "x" * 241})
    hypothesis = {**value["hypotheses"][0], "statement": "x" * 161}
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({**value, "hypotheses": [hypothesis]})
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({
            **value,
            "hypotheses": [value["hypotheses"][0]] * 4,
        })
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({
            **value,
            "hypotheses": [{**value["hypotheses"][0], "supporting_evidence": ["E-1"] * 5}],
        })
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({
            **value,
            "recommended_next_steps": ["Review access controls."] * 4,
        })
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({
            **value,
            "recommended_next_steps": ["x" * 121],
        })
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({
            **value,
            "unresolved_questions": ["x" * 121],
        })
    with pytest.raises(ValidationError):
        AnalystAssessment.model_validate({
            **value,
            "unresolved_questions": ["Open question?"] * 4,
        })


def test_gemini_is_the_default_configured_provider(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("OPENROUTER_MODEL", raising=False)
    settings = Settings.from_env()
    assert settings.llm_provider == "gemini"
    assert settings.gemini_model == "gemini-3.5-flash-lite"
    assert settings.openrouter_model == "nvidia/nemotron-3-super-120b-a12b:free"


@pytest.mark.parametrize("content", ["", "{}", "not json", '{{"classification":"needs_investigation"}}', '{"classification":"benign"}', "[]", None])
def test_invalid_structured_responses_fail_closed(content):
    reasoner = OpenAIReasoner(Settings(openai_api_key="test"), FakeClient(raw_response(content)))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == "llm_invalid_output"


def test_truncated_output_fails_closed(caplog):
    content = '{"classification":"needs_investigation"'
    reasoner = OpenRouterReasoner(
        Settings(openrouter_api_key="test", openrouter_model="configured"),
        FakeClient(raw_response(content, finish_reason="length")),
    )
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])

    assert error.value.code == "llm_invalid_output"
    assert "truncated output" in caplog.records[-1].message


def test_truncated_output_preserves_deterministic_fallback():
    reasoner = OpenRouterReasoner(
        Settings(openrouter_api_key="test", openrouter_model="configured"),
        FakeClient(raw_response('{"classification":"needs_investigation"', finish_reason="length")),
    )
    report = InvestigationService(
        settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=reasoner
    ).investigate(request())

    assert report.llm_assessment is None
    assert report.llm_failure_reason == "llm_invalid_output"
    assert report.final_assessment == report.deterministic_assessment


def test_missing_choices_fail_as_invalid_output():
    client = FakeClient(type("Response", (), {"choices": []})())
    with pytest.raises(LLMError) as error:
        OpenAIReasoner(Settings(openai_api_key="test"), client).analyze(request(), [], [], [], [])
    assert error.value.code == "llm_invalid_output"


@pytest.mark.parametrize(
    ("response_value", "diagnostic"),
    [
        (raw_response(""), "empty content"),
        (raw_response("not json"), "invalid JSON"),
        (raw_response("{}"), "schema validation failure"),
        (type("Response", (), {"choices": [type("Choice", (), {"message": type("Message", (), {"content": None, "refusal": "declined"})(), "finish_reason": "stop"})()]})(), "provider refusal"),
        (type("Response", (), {"choices": []})(), "unexpected response structure"),
    ],
)
def test_invalid_output_diagnostics_are_bounded_and_categorized(caplog, response_value, diagnostic):
    reasoner = OpenRouterReasoner(Settings(openrouter_api_key="test", openrouter_model="configured"), FakeClient(response_value))
    with pytest.raises(LLMError):
        reasoner.analyze(request(), [], [], [], [])

    record = caplog.records[-1]
    assert diagnostic in record.message
    assert "provider=openrouter model=configured" in record.message
    assert "response_format=json_schema" in record.message


def test_invalid_output_diagnostic_logs_only_the_first_1000_content_characters(caplog):
    content = "x" * 1001
    reasoner = OpenRouterReasoner(Settings(openrouter_api_key="test", openrouter_model="configured"), FakeClient(raw_response(content)))
    with pytest.raises(LLMError):
        reasoner.analyze(request(), [], [], [], [])

    record = caplog.records[-1]
    assert "content_length=1001" in record.message
    assert content[:1000] in record.message
    assert content not in record.message


def test_input_limit_is_enforced_before_provider_request():
    size = len(llm_input(request(), [], [], [], [], 1_000_000).encode())
    client = FakeClient(response(assessment()))
    reasoner = OpenAIReasoner(Settings(openai_api_key="test", llm_max_input_bytes=size), client)
    assert isinstance(reasoner.analyze(request(), [], [], [], []), AnalystAssessment)
    assert client.calls == 1

    client = FakeClient(response(assessment()))
    reasoner = OpenAIReasoner(Settings(openai_api_key="test", llm_max_input_bytes=size - 1), client)
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == "llm_error"
    assert client.calls == 0


def test_openai_falls_back_to_configured_openrouter_model():
    pinned = "nvidia/nemotron-3-super-120b-a12b:free"
    reasoner = create_reasoner(Settings(llm_provider="openai", openai_api_key="test", openrouter_api_key="test", openrouter_model=pinned))
    assert isinstance(reasoner, FallbackReasoner)
    reasoner.primary.client = FakeClient(error=ProviderError(503))
    reasoner.fallback.client = FakeClient(response(assessment()))
    result = reasoner.analyze(request(), [], [], [], [])
    assert isinstance(result, AnalystAssessment)
    assert reasoner.primary.client.calls == 2
    assert reasoner.fallback.client.called["model"] == pinned
    assert (reasoner.provider, reasoner.model, reasoner.fallback_used, reasoner.primary_failure_reason) == ("openrouter", pinned, True, "llm_unavailable")


def test_gemini_falls_back_to_openai():
    reasoner = create_reasoner(Settings(llm_provider="gemini", gemini_api_key="test", openai_api_key="test"))
    assert isinstance(reasoner, FallbackReasoner) and len(reasoner.fallbacks) == 1
    reasoner.primary.client = FakeGeminiClient(error=ProviderError(503))
    reasoner.fallbacks[0].client = FakeClient(response(assessment()))
    assert isinstance(reasoner.analyze(request(), [], [], [], []), AnalystAssessment)
    assert reasoner.primary.client.calls == 2
    assert (reasoner.provider, reasoner.model, reasoner.fallback_used, reasoner.primary_failure_reason) == (
        "openai", "gpt-6-luna", True, "llm_unavailable"
    )


def test_gemini_success_does_not_fallback():
    reasoner = create_reasoner(Settings(
        llm_provider="gemini", gemini_api_key="test", openai_api_key="test", openrouter_api_key="test",
    ))
    reasoner.primary.client = FakeGeminiClient(gemini_response(json.dumps(assessment().model_dump())))
    reasoner.fallbacks[0].client = FakeClient(error=ProviderError(503))
    reasoner.fallbacks[1].client = FakeClient(error=ProviderError(503))
    assert isinstance(reasoner.analyze(request(), [], [], [], []), AnalystAssessment)
    assert reasoner.provider == "gemini"
    assert not reasoner.fallback_used and reasoner.primary_failure_reason is None
    assert reasoner.fallbacks[0].client.calls == 0
    assert reasoner.fallbacks[1].client.calls == 0


def test_gemini_fallback_stops_after_openai_success():
    reasoner = create_reasoner(Settings(
        llm_provider="gemini", gemini_api_key="test", openai_api_key="test", openrouter_api_key="test",
    ))
    reasoner.primary.client = FakeGeminiClient(error=ProviderError(503))
    reasoner.fallbacks[0].client = FakeClient(response(assessment()))
    reasoner.fallbacks[1].client = FakeClient(error=ProviderError(503))
    assert isinstance(reasoner.analyze(request(), [], [], [], []), AnalystAssessment)
    assert reasoner.provider == "openai" and reasoner.fallback_used
    assert reasoner.fallbacks[1].client.calls == 0


def test_non_transient_gemini_failure_does_not_fallback():
    reasoner = create_reasoner(Settings(
        llm_provider="gemini", gemini_api_key="test", openai_api_key="test", openrouter_api_key="test",
    ))
    reasoner.primary.client = FakeGeminiClient(error=ProviderError(400))
    reasoner.fallbacks[0].client = FakeClient(response(assessment()))
    reasoner.fallbacks[1].client = FakeClient(response(assessment()))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == "llm_error"
    assert not reasoner.fallback_used
    assert reasoner.fallbacks[0].client.calls == 0
    assert reasoner.fallbacks[1].client.calls == 0


def test_gemini_falls_back_through_openai_to_openrouter():
    reasoner = create_reasoner(Settings(
        llm_provider="gemini", gemini_api_key="test", openai_api_key="test",
        openrouter_api_key="test", openrouter_model="pinned/model",
    ))
    assert isinstance(reasoner, FallbackReasoner) and len(reasoner.fallbacks) == 2
    reasoner.primary.client = FakeGeminiClient(error=ProviderError(503))
    reasoner.fallbacks[0].client = FakeClient(error=ProviderError(503))
    reasoner.fallbacks[1].client = FakeClient(response(assessment()))
    assert isinstance(reasoner.analyze(request(), [], [], [], []), AnalystAssessment)
    assert reasoner.primary.client.calls == 2
    assert reasoner.fallbacks[0].client.calls == 1
    assert (reasoner.provider, reasoner.model, reasoner.fallback_used, reasoner.primary_failure_reason) == (
        "openrouter", "pinned/model", True, "llm_unavailable"
    )


def test_openrouter_has_no_fallback():
    reasoner = create_reasoner(Settings(llm_provider="openrouter", openrouter_api_key="test"))
    assert isinstance(reasoner, OpenRouterReasoner)
    reasoner.client = FakeClient(error=ProviderError(503))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == "llm_unavailable"
    assert reasoner.client.calls == 1


@pytest.mark.parametrize("status, code", [(429, "llm_quota_exhausted"), (503, "llm_unavailable")])
def test_openai_http_errors_are_classified(status, code):
    reasoner = OpenAIReasoner(Settings(openai_api_key="test"), FakeClient(error=ProviderError(status)))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == code and error.value.transient


@pytest.mark.parametrize("error", [ProviderError(429), ProviderError(503), TimeoutError()])
def test_transient_openai_failure_retries_once_then_falls_back(error):
    primary = FakeReasoner("openai", "primary", [LLMError("llm_quota_exhausted", transient=True) if isinstance(error, ProviderError) and error.status_code == 429 else LLMError("llm_unavailable" if isinstance(error, ProviderError) else "llm_timeout", transient=True), LLMError("llm_unavailable", transient=True)])
    fallback = FakeReasoner("openrouter", "fallback", [assessment()])
    reasoner = FallbackReasoner(primary, fallback)
    assert reasoner.analyze(None, [], [], [], []).automated_action == "none"
    assert primary.calls == 2
    assert fallback.calls == 1
    assert reasoner.fallback_used and reasoner.provider == "openrouter"


def test_invalid_output_and_validation_failures_do_not_fallback():
    primary = FakeReasoner("openai", "primary", [LLMError("llm_invalid_output")])
    fallback = FakeReasoner("openrouter", "fallback", [assessment()])
    with pytest.raises(LLMError):
        FallbackReasoner(primary, fallback).analyze(None, [], [], [], [])
    assert fallback.calls == 0
    invalid = assessment("unknown")
    with pytest.raises(ValueError):
        validate_assessment(invalid, {"E-1"}, {"H-001"}, [])


def test_invalid_gemini_output_does_not_trigger_openai():
    reasoner = create_reasoner(Settings(llm_provider="gemini", gemini_api_key="test", openai_api_key="test"))
    reasoner.primary.client = FakeGeminiClient(gemini_response("{"))
    reasoner.fallback.client = FakeClient(response(assessment()))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == "llm_invalid_output"
    assert reasoner.fallback.client.calls == 0


def test_invalid_openai_response_does_not_trigger_openrouter():
    reasoner = create_reasoner(Settings(llm_provider="openai", openai_api_key="test", openrouter_api_key="test", openrouter_model="pinned/model"))
    reasoner.primary.client = FakeClient(raw_response("{}"))
    reasoner.fallback.client = FakeClient(response(assessment()))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == "llm_invalid_output"
    assert reasoner.primary.client.calls == 1
    assert reasoner.fallback.client.calls == 0


def test_non_transient_primary_failure_does_not_call_openrouter():
    reasoner = create_reasoner(Settings(llm_provider="openai", openai_api_key="test", openrouter_api_key="test", openrouter_model="pinned/model"))
    reasoner.primary.client = FakeClient(error=ProviderError(400))
    reasoner.fallback.client = FakeClient(response(assessment()))
    with pytest.raises(LLMError) as error:
        reasoner.analyze(request(), [], [], [], [])
    assert error.value.code == "llm_error"
    assert reasoner.primary.client.calls == 1
    assert reasoner.fallback.client.calls == 0
    assert reasoner.provider == "openai" and not reasoner.fallback_used


def test_reused_reasoner_reports_primary_after_fallback():
    primary = FakeReasoner("openai", "primary", [LLMError("llm_timeout", transient=True), LLMError("llm_timeout", transient=True), assessment()])
    fallback = FakeReasoner("openrouter", "pinned/model", [assessment()])
    reasoner = FallbackReasoner(primary, fallback)
    reasoner.analyze(None, [], [], [], [])
    assert reasoner.provider == "openrouter" and reasoner.fallback_used
    reasoner.analyze(None, [], [], [], [])
    assert (reasoner.provider, reasoner.model, reasoner.fallback_used, reasoner.primary_failure_reason) == ("openai", "primary", False, None)


def test_validation_failure_does_not_invoke_fallback_provider():
    primary = FakeReasoner("openai", "primary", [assessment("unknown")])
    fallback = FakeReasoner("openrouter", "fallback", [assessment()])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=FallbackReasoner(primary, fallback)).investigate(request())
    assert report.llm_failure_reason == "llm_validation_failed"
    assert fallback.calls == 0
    assert report.final_assessment.classification == report.deterministic_assessment.classification
    assert report.assessment_consistency.status == "consistent"


def test_consistency_validation_failure_fails_closed(monkeypatch):
    import app.service as service_module

    reconcile = service_module.reconcile_assessment

    def invalid_consistency(assessment_value, *args):
        if assessment_value is not None:
            raise ValueError("invalid consistency")
        return reconcile(None, *args)

    monkeypatch.setattr(service_module, "reconcile_assessment", invalid_consistency)
    reasoner = FakeReasoner(
        "test", "test", [lambda alert, evidence, hypotheses, missing, activity: assessment(evidence[0].id, hypotheses[0].id)]
    )
    report = InvestigationService(
        settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=reasoner
    ).investigate(request())

    assert report.assessment_consistency.status == "invalid"
    assert report.llm_assessment is not None
    assert report.final_assessment.classification == report.deterministic_assessment.classification
    assert report.final_assessment.source == "deterministic"


def test_unknown_hypothesis_missing_review_and_automated_action_are_rejected():
    valid = assessment()
    with pytest.raises(ValueError):
        validate_assessment(valid.model_copy(update={"hypotheses": [valid.hypotheses[0].model_copy(update={"id": "H-999"})]}), {"E-1"}, {"H-001"}, [])
    with pytest.raises(ValueError):
        validate_assessment(valid.model_copy(update={"human_review_required": False}), {"E-1"}, {"H-001"}, ["Historical access activity"])
    assert AnalystAssessment.model_validate({**valid.model_dump(), "automated_action": "none"}).automated_action == "none"


def test_both_provider_failures_preserve_deterministic_report():
    primary = FakeReasoner("openai", "primary", [LLMError("llm_unavailable", transient=True), LLMError("llm_unavailable", transient=True)])
    fallback = FakeReasoner("openrouter", "fallback", [LLMError("llm_unavailable", transient=True)])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=FallbackReasoner(primary, fallback)).investigate(request())
    assert report.state.status == "partial"
    assert report.llm_assessment is None
    assert report.final_assessment.classification == report.deterministic_assessment.classification
    assert report.final_assessment.source == "deterministic"
    assert report.llm_provider == "openrouter"
    assert report.llm_fallback_used
    assert report.llm_primary_failure_reason == "llm_unavailable"
    assert report.automated_action == "none"


def test_successful_provider_metadata_and_validation_failure_are_reported():
    success = FakeReasoner("openai", "gpt-6-luna", [lambda alert, evidence, hypotheses, missing, activity: assessment(evidence[0].id, hypotheses[0].id)])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=success).investigate(request())
    assert report.llm_status == "success"
    assert report.llm_provider == "openai"
    assert report.llm_model == "gpt-6-luna"
    invalid = FakeReasoner("openai", "primary", [assessment("unknown")])
    report = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]), llm_reasoner=invalid).investigate(request())
    assert report.llm_failure_reason == "llm_validation_failed"
    assert report.llm_assessment is None
    assert report.final_assessment.classification == report.deterministic_assessment.classification
