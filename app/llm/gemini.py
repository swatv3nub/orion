from __future__ import annotations

import json
import logging
from copy import deepcopy
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from pydantic import ValidationError

from app.config import Settings
from app.llm.base import LLMError, LLMReasoner, SYSTEM_PROMPT, llm_input
from app.llm.schemas import AnalystAssessment
from app.models import Evidence, Hypothesis, ThreatLensAlert, ToolActivity

logger = logging.getLogger(__name__)


class GeminiReasoner(LLMReasoner):
    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        self.provider = "gemini"
        self.api_key = settings.gemini_api_key
        self.base_url = settings.gemini_base_url
        self.model = settings.gemini_model
        self.timeout = max(settings.gemini_connect_timeout_seconds, settings.gemini_read_timeout_seconds)
        self.max_input_bytes = settings.llm_max_input_bytes
        self.max_output_tokens = settings.llm_max_output_tokens
        self.client = client

    def analyze(self, alert: ThreatLensAlert, evidence: list[Evidence], hypotheses: list[Hypothesis], missing_evidence: list[str], tool_activity: list[ToolActivity]) -> AnalystAssessment:
        if not self.api_key or not self.model:
            raise LLMError("llm_error", "LLM provider is not configured")
        payload = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": llm_input(alert, evidence, hypotheses, missing_evidence, tool_activity, self.max_input_bytes)}]}],
            "generationConfig": {
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
                "responseSchema": gemini_schema(AnalystAssessment.model_json_schema()),
            },
        }
        try:
            response = self._post(payload)
        except LLMError:
            raise
        except Exception as exc:
            raise self._error(exc) from None
        error = response.get("error") if isinstance(response, dict) else None
        if not isinstance(response, dict) or error:
            status = error.get("code") if isinstance(error, dict) else None
            raise self._status_error(status)
        try:
            candidate = response["candidates"][0]
            content = candidate["content"]
            text = content["parts"][0]["text"]
            finish_reason = candidate["finishReason"]
        except (TypeError, KeyError, IndexError) as exc:
            self._log_invalid_output("unexpected response structure", None, None, exc)
            raise LLMError("llm_invalid_output") from exc
        if finish_reason != "STOP":
            exc = ValueError("Gemini response was incomplete")
            self._log_invalid_output("incomplete output", text if isinstance(text, str) else None, finish_reason, exc)
            raise LLMError("llm_invalid_output") from exc
        if not isinstance(text, str) or not text.strip():
            exc = ValueError("Gemini returned empty content")
            self._log_invalid_output("empty content", text if isinstance(text, str) else None, finish_reason, exc)
            raise LLMError("llm_invalid_output") from exc
        try:
            return AnalystAssessment.model_validate(json.loads(text))
        except (json.JSONDecodeError, TypeError) as exc:
            self._log_invalid_output("invalid JSON", text, finish_reason, exc)
            raise LLMError("llm_invalid_output") from exc
        except ValidationError as exc:
            self._log_invalid_output("schema validation failure", text, finish_reason, exc)
            raise LLMError("llm_invalid_output") from exc

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url.rstrip('/')}/models/{quote(self.model, safe='-_.')}:generateContent"
        if self.client is not None:
            return self.client.post(url, json=payload, headers={"x-goog-api-key": self.api_key}, timeout=self.timeout)
        request = Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "x-goog-api-key": self.api_key}, method="POST")
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read())
        except HTTPError as exc:
            raise self._status_error(exc.code) from None
        except (TimeoutError, URLError, OSError) as exc:
            raise self._error(exc) from None

    def _status_error(self, status: Any) -> LLMError:
        try:
            status = int(status)
        except (TypeError, ValueError):
            return LLMError("llm_error")
        if status == 429:
            return LLMError("llm_quota_exhausted", transient=True)
        if status in {500, 502, 503, 504}:
            return LLMError("llm_unavailable", transient=True)
        return LLMError("llm_error")

    def _error(self, exc: Exception) -> LLMError:
        if isinstance(exc, TimeoutError):
            return LLMError("llm_timeout", transient=True)
        if isinstance(exc, (ConnectionError, OSError)) or type(exc).__name__ == "APIConnectionError":
            return LLMError("llm_unavailable", transient=True)
        return self._status_error(getattr(exc, "status_code", None))

    def _log_invalid_output(self, failure: str, text: str | None, finish_reason: Any, exc: Exception) -> None:
        if isinstance(exc, ValidationError):
            errors = exc.errors()
            logger.warning(
                "Gemini response %s provider=%s model=%s finish_reason=%r content_length=%s exception_class=%s validation_errors=%r",
                failure,
                self.provider,
                self.model,
                finish_reason,
                len(text) if isinstance(text, str) else None,
                type(exc).__name__,
                errors,
                extra={"validation_errors": errors},
            )
            print(
                "GEMINI_VALIDATION_ERROR:",
                repr(errors),
                flush=True,
            )
            return
        logger.warning(
            "Gemini response %s provider=%s model=%s finish_reason=%r content_length=%s exception_class=%s",
            failure, self.provider, self.model, finish_reason, len(text) if isinstance(text, str) else None, type(exc).__name__,
        )


def gemini_schema(schema: dict[str, Any]) -> dict[str, Any]:
    definitions = schema.get("$defs", {})

    def convert(value: Any) -> Any:
        if isinstance(value, list):
            return [convert(item) for item in value]
        if not isinstance(value, dict):
            return value
        if "$ref" in value:
            return convert(deepcopy(definitions[value["$ref"].rsplit("/", 1)[-1]]))
        result = {key: convert(item) for key, item in value.items() if key not in {"$defs", "title", "default", "additionalProperties"}}
        if "const" in result:
            result["enum"] = [result.pop("const")]
        if "type" in result:
            result["type"] = result["type"].upper()
        return result

    return convert(schema)
