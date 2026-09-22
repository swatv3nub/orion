from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AnalystHypothesis(BaseModel):
    id: str
    statement: str
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    status: Literal["supported", "partially_supported", "unresolved", "contradicted"]


class AnalystAssessment(BaseModel):
    classification: Literal["benign", "needs_investigation", "suspicious", "confirmed"]
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    hypotheses: list[AnalystHypothesis] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    human_review_required: bool
    automated_action: Literal["none"]


def validate_assessment(assessment: AnalystAssessment, evidence_ids: set[str], hypothesis_ids: set[str], missing_evidence: list[str]) -> AnalystAssessment:
    references = assessment.supporting_evidence + assessment.contradicting_evidence
    references += [item for hypothesis in assessment.hypotheses for item in hypothesis.supporting_evidence + hypothesis.contradicting_evidence]
    if not set(references) <= evidence_ids:
        raise ValueError("LLM assessment referenced unknown evidence")
    if not {hypothesis.id for hypothesis in assessment.hypotheses} <= hypothesis_ids:
        raise ValueError("LLM assessment referenced unknown hypothesis")
    if assessment.automated_action != "none":
        raise ValueError("LLM assessment requested an automated action")
    if missing_evidence and not assessment.human_review_required:
        raise ValueError("LLM assessment removed required human review")
    return assessment
