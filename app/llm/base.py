from __future__ import annotations

from abc import ABC, abstractmethod
import json

from app.llm.schemas import AnalystAssessment
from app.models import Evidence, Hypothesis, ThreatLensAlert, ToolActivity


class LLMError(Exception):
    def __init__(self, code: str, message: str | None = None, transient: bool = False) -> None:
        self.code = code
        self.transient = transient
        super().__init__(message or code)


class LLMReasoner(ABC):
    provider: str = ""
    model: str = ""
    fallback_used: bool = False
    primary_failure_reason: str | None = None
    @abstractmethod
    def analyze(self, alert: ThreatLensAlert, evidence: list[Evidence], hypotheses: list[Hypothesis], missing_evidence: list[str], tool_activity: list[ToolActivity]) -> AnalystAssessment:
        raise NotImplementedError


def llm_input(alert: ThreatLensAlert, evidence: list[Evidence], hypotheses: list[Hypothesis], missing_evidence: list[str], tool_activity: list[ToolActivity], max_bytes: int) -> str:
    payload = {
        "alert": alert.model_dump(mode="json"),
        "verified_evidence": [item.model_dump(mode="json") for item in evidence],
        "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
        "missing_evidence": missing_evidence,
        "tool_activity": [item.model_dump(mode="json") for item in tool_activity],
    }
    contents = json.dumps(payload, separators=(",", ":"))
    if len(contents.encode()) > max_bytes:
        raise LLMError("llm_error", "LLM input exceeded size limit")
    return contents
