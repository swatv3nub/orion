from __future__ import annotations

import json
from typing import Any

from app.llm.base import LLMError, LLMReasoner, llm_input
from app.llm.schemas import AnalystAssessment
from app.models import Evidence, Hypothesis, ThreatLensAlert, ToolActivity


SYSTEM_PROMPT = """You are an analyst-assistance component inside ORION. Analyze only supplied alert, verified evidence, hypotheses, missing evidence, and tool activity. Do not invent facts, evidence, network activity, IP ownership, authentication state, identities, asset criticality, vulnerability, exploitation, historical activity, MITRE techniques, or remediation. Every factual summary, claim, and hypothesis statement must cite supplied evidence IDs. State when evidence is insufficient. Recommended next steps must be actions or questions, not factual claims. Unresolved questions are not facts. Human review is required when evidence is insufficient. automated_action must be none."""


class OpenAICompatibleReasoner(LLMReasoner):
    def __init__(self, provider: str, api_key: str, base_url: str, model: str, connect_timeout: float, read_timeout: float, max_input_bytes: int, max_output_tokens: int, client: Any | None = None) -> None:
        self.provider = provider
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.timeout = max(connect_timeout, read_timeout)
        self.max_input_bytes = max_input_bytes
        self.max_output_tokens = max_output_tokens
        self.client = client

    def analyze(self, alert: ThreatLensAlert, evidence: list[Evidence], hypotheses: list[Hypothesis], missing_evidence: list[str], tool_activity: list[ToolActivity]) -> AnalystAssessment:
        if not self.api_key or not self.model:
            raise LLMError("llm_error", "LLM provider is not configured")
        contents = llm_input(alert, evidence, hypotheses, missing_evidence, tool_activity, self.max_input_bytes)
        try:
            response = self._client().chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": contents}],
                response_format={"type": "json_schema", "json_schema": {"name": "analyst_assessment", "strict": True, "schema": strict_schema(AnalystAssessment.model_json_schema())}},
                max_tokens=self.max_output_tokens,
            )
        except LLMError:
            raise
        except Exception as exc:
            raise self._error(exc) from exc
        try:
            return AnalystAssessment.model_validate(json.loads(response.choices[0].message.content))
        except (ValueError, TypeError, AttributeError, IndexError, KeyError) as exc:
            raise LLMError("llm_invalid_output") from exc

    def _client(self) -> Any:
        if self.client is not None:
            return self.client
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=self.timeout)
            return self.client
        except Exception as exc:
            raise LLMError("llm_error", "OpenAI-compatible SDK is unavailable") from exc

    def _error(self, exc: Exception) -> LLMError:
        if isinstance(exc, TimeoutError):
            return LLMError("llm_timeout", transient=True)
        if isinstance(exc, (ConnectionError, OSError)) or type(exc).__name__ == "APIConnectionError":
            return LLMError("llm_unavailable", transient=True)
        status = getattr(exc, "status_code", None)
        try:
            status = int(status)
        except (TypeError, ValueError):
            pass
        if status == 429:
            return LLMError("llm_quota_exhausted", transient=True)
        if status in {500, 502, 503, 504}:
            return LLMError("llm_unavailable", transient=True)
        return LLMError("llm_error")


def strict_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Add the strict object constraints required by OpenAI-compatible APIs."""
    if isinstance(schema, dict):
        if schema.get("type") == "object" and "properties" in schema:
            schema["additionalProperties"] = False
            schema["required"] = list(schema["properties"])
        for value in schema.values():
            strict_schema(value)
    elif isinstance(schema, list):
        for value in schema:
            strict_schema(value)
    return schema
