from __future__ import annotations

from app.llm.schemas import AnalystAssessment
from app.models import (
    AssessmentConsistency,
    AssessmentConsistencyStatus,
    AssessmentSource,
    Evaluation,
    FinalAssessment,
    Hypothesis,
    HypothesisStatus,
    Severity,
)


_SECURITY_CONTEXT_GAPS = {
    "Expected exposure status",
    "Service ownership",
    "Authentication and access-control configuration",
    "Cloud resource ownership",
    "Cloud access-control configuration",
    "Intended public or private state of the cloud resource",
    "Intended public or private state",
    "Vulnerability verification",
    "Exploitation evidence",
    "Business impact",
}


def reconcile_assessment(
    assessment: AnalystAssessment | None,
    evaluation: Evaluation,
    severity: Severity,
    hypotheses: list[Hypothesis],
) -> tuple[FinalAssessment, FinalAssessment, AssessmentConsistency]:
    deterministic = FinalAssessment(
        classification=evaluation.classification.value,
        severity=severity,
        confidence=evaluation.confidence,
        rationale="Deterministic investigation evidence is insufficient to establish a confirmed security condition.",
        source=AssessmentSource.deterministic,
    )
    if assessment is None:
        return deterministic, deterministic, AssessmentConsistency(
            status=AssessmentConsistencyStatus.consistent,
            reason="The deterministic assessment is used because no validated LLM assessment is available.",
        )

    blockers: set[str] = set()
    missing_context: set[str] = set()
    lacks_supported_hypothesis = False
    if assessment.classification == "confirmed":
        by_id = {hypothesis.id: hypothesis for hypothesis in hypotheses}
        aligned = False
        for proposed in assessment.hypotheses:
            deterministic_hypothesis = by_id.get(proposed.id)
            if deterministic_hypothesis is None:
                continue
            # Only evidence-linked hypotheses can make deterministic gaps relevant.
            if not set(proposed.evidence_refs) & set(deterministic_hypothesis.supporting_evidence):
                continue
            aligned = True
            missing_context.update(set(deterministic_hypothesis.missing_evidence) & _SECURITY_CONTEXT_GAPS)
            if deterministic_hypothesis.status != HypothesisStatus.supported:
                lacks_supported_hypothesis = True
        if not aligned:
            lacks_supported_hypothesis = True
        if assessment.confidence < 0.75:
            blockers.add("LLM confidence is below the confirmed-assessment threshold")

    if blockers or missing_context or lacks_supported_hypothesis:
        reason = "The LLM assessment identifies verified observations but does not establish the security context required for a confirmed classification."
        if missing_context:
            reason += " Missing evidence includes: " + ", ".join(sorted(missing_context)) + "."
        if lacks_supported_hypothesis:
            reason += " The deterministic assessment does not contain a supported hypothesis meeting the confirmation threshold."
        if blockers:
            reason += " " + "; ".join(sorted(blockers)) + "."
        reason += " The deterministic assessment therefore remains needs_investigation."
        final = deterministic.model_copy(update={"rationale": reason, "source": AssessmentSource.reconciled})
        status = AssessmentConsistencyStatus.reconciled
    else:
        llm_classification = assessment.classification
        # The report's legacy classification remains the deterministic value; this
        # added final assessment can use the LLM vocabulary, including "confirmed".
        disagrees = llm_classification != deterministic.classification.value
        final = FinalAssessment(
            classification=llm_classification,
            severity=assessment.severity,
            confidence=assessment.confidence,
            rationale=assessment.summary,
            source=AssessmentSource.reconciled if disagrees else AssessmentSource.llm,
        )
        status = AssessmentConsistencyStatus.reconciled if disagrees else AssessmentConsistencyStatus.consistent
        reason = (
            "The validated LLM classification differs from the deterministic assessment and is accepted by the evidence policy."
            if disagrees
            else "The validated LLM assessment is supported by the relevant investigation evidence."
        )
    return deterministic, final, AssessmentConsistency(status=status, reason=reason)
