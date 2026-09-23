from __future__ import annotations

import json
import logging
from typing import Any

from pydantic import ValidationError

from app.llm.base import LLMError, LLMReasoner, llm_input
from app.llm.schemas import AnalystAssessment
from app.models import Evidence, Hypothesis, ThreatLensAlert, ToolActivity


SYSTEM_PROMPT = """You are an analyst-assistance component inside ORION. Analyze only supplied alert, verified evidence, hypotheses, missing evidence, and tool activity. Return exactly one JSON object matching the schema, with one opening and closing brace; no preamble, markdown, or trailing text. Strongly prefer the shortest valid response: omit nonessential claims, use empty arrays when no items are needed, and do not restate alert or evidence metadata supplied by ORION. Do not duplicate braces. Do not invent facts, evidence, network activity, IP ownership, authentication state, identities, asset criticality, vulnerability, exploitation, historical activity, MITRE techniques, or remediation. Every factual summary, claim, and hypothesis statement must cite supplied evidence IDs. Never repeat evidence descriptions; reference evidence IDs only. Keep the summary under 240 characters; return at most three hypotheses with statements under 160 characters and at most four supporting evidence IDs each; return at most three unresolved questions and three recommended next steps, each under 120 characters. State when evidence is insufficient. Recommended next steps must be actions or questions, not factual claims. Unresolved questions are not facts. Keep human_review_required explicit. automated_action must be none."""

logger = logging.getLogger(__name__)


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
        response_format_mode = "json_schema"
        try:
            choice = response.choices[0]
            message = choice.message
            content = message.content
            finish_reason = getattr(choice, "finish_reason", None)
        except (TypeError, AttributeError, IndexError, KeyError) as exc:
            self._log_invalid_output("unexpected response structure", None, None, response_format_mode, exc)
            raise LLMError("llm_invalid_output") from exc

        if getattr(message, "refusal", None):
            exc = ValueError("Provider returned a refusal")
            self._log_invalid_output("provider refusal", content, finish_reason, response_format_mode, exc)
            raise LLMError("llm_invalid_output") from exc
        if content is None or (isinstance(content, str) and not content.strip()):
            exc = ValueError("Provider returned empty content")
            self._log_invalid_output("empty content", content, finish_reason, response_format_mode, exc)
            raise LLMError("llm_invalid_output") from exc
        if not isinstance(content, str):
            exc = TypeError("Provider response content is not a string")
            self._log_invalid_output("unexpected response structure", None, finish_reason, response_format_mode, exc)
            raise LLMError("llm_invalid_output") from exc
        if finish_reason == "length":
            exc = ValueError("Provider output was truncated")
            self._log_invalid_output("truncated output", content, finish_reason, response_format_mode, exc)
            raise LLMError("llm_invalid_output") from exc
        try:
            parsed = json.loads(content)
        except (json.JSONDecodeError, TypeError) as exc:
            self._log_invalid_output("invalid JSON", content, finish_reason, response_format_mode, exc)
            raise LLMError("llm_invalid_output") from exc
        try:
            return AnalystAssessment.model_validate(parsed)
        except ValidationError as exc:
            self._log_invalid_output("schema validation failure", content, finish_reason, response_format_mode, exc)
            raise LLMError("llm_invalid_output") from exc

    def _log_invalid_output(self, failure: str, content: str | None, finish_reason: Any, response_format_mode: str, exc: Exception) -> None:
        """Log bounded response diagnostics without recording request data or full output."""
        content_preview = content[:1000] if isinstance(content, str) else None
        exception_message = str(exc)[:1000]
        logger.warning(
            "LLM response %s provider=%s model=%s finish_reason=%r content_length=%s "
            "content_preview=%r response_format=%s exception_class=%s exception_message=%r",
            failure,
            self.provider,
            self.model,
            finish_reason,
            len(content) if isinstance(content, str) else None,
            content_preview,
            response_format_mode,
            type(exc).__name__,
            exception_message,
        )

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
