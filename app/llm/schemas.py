from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AnalystHypothesis(BaseModel):
    id: str
    statement: str
    evidence_refs: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    status: Literal["supported", "partially_supported", "unresolved", "contradicted"]


class AnalystClaim(BaseModel):
    text: str
    evidence_refs: list[str] = Field(min_length=1)


class AnalystAssessment(BaseModel):
    classification: Literal["benign", "needs_investigation", "suspicious", "confirmed"]
    severity: Literal["informational", "low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    summary_evidence_refs: list[str] = Field(min_length=1)
    factual_claims: list[AnalystClaim] = Field(default_factory=list)
    hypotheses: list[AnalystHypothesis] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    unresolved_questions: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)
    human_review_required: bool
    automated_action: Literal["none"]


def validate_assessment(assessment: AnalystAssessment, evidence_ids: set[str], hypothesis_ids: set[str], missing_evidence: list[str]) -> AnalystAssessment:
    references = assessment.summary_evidence_refs + assessment.supporting_evidence + assessment.contradicting_evidence
    references += [item for claim in assessment.factual_claims for item in claim.evidence_refs]
    references += [item for hypothesis in assessment.hypotheses for item in hypothesis.evidence_refs + hypothesis.supporting_evidence + hypothesis.contradicting_evidence]
    if not set(references) <= evidence_ids:
        raise ValueError("LLM assessment referenced unknown evidence")
    if not {hypothesis.id for hypothesis in assessment.hypotheses} <= hypothesis_ids:
        raise ValueError("LLM assessment referenced unknown hypothesis")
    if assessment.automated_action != "none":
        raise ValueError("LLM assessment requested an automated action")
    if missing_evidence and not assessment.human_review_required:
        raise ValueError("LLM assessment removed required human review")
    return assessment
