from __future__ import annotations

from abc import ABC, abstractmethod
import json

from app.llm.schemas import AnalystAssessment
from app.models import Evidence, Hypothesis, ThreatLensAlert, ToolActivity


SYSTEM_PROMPT = """You are an analyst-assistance component inside ORION. Analyze only supplied alert, verified evidence, hypotheses, missing evidence, and tool activity. Return exactly one JSON object matching the schema, with one opening and closing brace; no preamble, markdown, or trailing text. Strongly prefer the shortest valid response: omit nonessential claims, use empty arrays when no items are needed, and do not restate alert or evidence metadata supplied by ORION. Do not duplicate braces. Do not invent facts, evidence, network activity, IP ownership, authentication state, identities, asset criticality, vulnerability, exploitation, historical activity, MITRE techniques, or remediation. Every factual summary, claim, and hypothesis statement must cite supplied evidence IDs. Never repeat evidence descriptions; reference evidence IDs only. Keep the summary under 240 characters; return at most three hypotheses with statements under 160 characters and at most four supporting evidence IDs each; return at most three unresolved questions and three recommended next steps, each under 120 characters. State when evidence is insufficient. Recommended next steps must be actions or questions, not factual claims. Unresolved questions are not facts. Keep human_review_required explicit. automated_action must be none."""


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
