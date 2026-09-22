from __future__ import annotations

from abc import ABC, abstractmethod

from app.llm.schemas import AnalystAssessment
from app.models import Evidence, Hypothesis, ThreatLensAlert, ToolActivity


class LLMError(Exception):
    pass


class LLMReasoner(ABC):
    @abstractmethod
    def analyze(self, alert: ThreatLensAlert, evidence: list[Evidence], hypotheses: list[Hypothesis], missing_evidence: list[str], tool_activity: list[ToolActivity]) -> AnalystAssessment:
        raise NotImplementedError
