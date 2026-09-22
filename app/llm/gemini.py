from __future__ import annotations

import json
from typing import Any

from app.config import Settings
from app.llm.base import LLMError, LLMReasoner
from app.llm.schemas import AnalystAssessment
from app.models import Evidence, Hypothesis, ThreatLensAlert, ToolActivity


SYSTEM_PROMPT = """You are an analyst-assistance component inside ORION. Analyze only the supplied alert, verified evidence, hypotheses, missing evidence, and tool activity. Do not invent facts, evidence, scan results, alerts, network activity, identities, IP ownership, payload contents, authentication state, user identity, asset criticality, vulnerability status, exploitation, MITRE techniques, historical activity, or remediation. Every factual summary and hypothesis statement must include one or more supplied evidence IDs in its evidence_refs. State that evidence is insufficient when appropriate. Frame recommended_next_steps as actions or questions, never as factual claims. Do not present unresolved_questions as established facts. Do not assume an exposed service is malicious. Human review is required when evidence is insufficient. automated_action must be none."""


class GeminiReasoner(LLMReasoner):
    def __init__(self, settings: Settings, client: Any | None = None, types: Any | None = None) -> None:
        self.settings = settings
        self.client = client
        self.types = types

    def analyze(self, alert: ThreatLensAlert, evidence: list[Evidence], hypotheses: list[Hypothesis], missing_evidence: list[str], tool_activity: list[ToolActivity]) -> AnalystAssessment:
        if not self.settings.gemini_api_key:
            raise LLMError("llm_error", "Gemini is not configured")
        payload = {
            "alert": alert.model_dump(mode="json"),
            "verified_evidence": [item.model_dump(mode="json") for item in evidence],
            "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
            "missing_evidence": missing_evidence,
            "tool_activity": [item.model_dump(mode="json") for item in tool_activity],
        }
        contents = json.dumps(payload, separators=(",", ":"))
        if len(contents.encode()) > self.settings.gemini_max_input_bytes:
            raise LLMError("llm_error", "Gemini input exceeded size limit")
        try:
            client, types = self._client()
            response = client.models.generate_content(
                model=self.settings.gemini_model,
                contents=contents,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    response_mime_type="application/json",
                    response_schema=AnalystAssessment,
                    max_output_tokens=self.settings.gemini_max_output_tokens,
                ),
            )
            parsed = getattr(response, "parsed", None)
            return AnalystAssessment.model_validate(parsed if parsed is not None else json.loads(response.text))
        except LLMError:
            raise
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            raise LLMError("llm_invalid_output") from exc
        except Exception as exc:
            raise LLMError(self._error_code(exc)) from exc

    def _client(self) -> tuple[Any, Any]:
        if self.client is not None and self.types is not None:
            return self.client, self.types
        try:
            from google import genai
            from google.genai import types
            self.client = genai.Client(
                api_key=self.settings.gemini_api_key,
                http_options=types.HttpOptions(timeout=int(max(self.settings.gemini_connect_timeout_seconds, self.settings.gemini_read_timeout_seconds) * 1000)),
            )
            self.types = types
            return self.client, types
        except Exception as exc:
            raise LLMError("llm_error", "Gemini SDK is unavailable") from exc

    def _error_code(self, exc: Exception) -> str:
        if isinstance(exc, TimeoutError):
            return "llm_timeout"
        status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
        try:
            status = int(status)
        except (TypeError, ValueError):
            pass
        if status == 429:
            return "llm_quota_exhausted"
        if status == 503:
            return "llm_unavailable"
        return "llm_error"
