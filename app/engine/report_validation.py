from __future__ import annotations

import re

from app.llm.schemas import AnalystAssessment, validate_assessment
from app.models import AnalystReport


class ReportIntegrityError(ValueError):
    """Raised when a report is not safe to publish as a coherent assessment."""


def final_assessment_summary(report: AnalystReport) -> str:
    """Return the canonical, deterministic final-assessment portion of a report."""
    assessment = report.final_assessment
    return (
        f"Final assessment: {assessment.classification} "
        f"({assessment.severity}, confidence {assessment.confidence:.2f})."
    )


def validate_report_integrity(report: AnalystReport) -> AnalystReport:
    """Validate the report boundary before it is persisted or returned.

    ``final_assessment`` is the only authority for the final assessment prose.
    LLM content remains separately stored and is validated as attributed input;
    it is never used to construct the report's final assessment statement.
    The top-level legacy classification, severity, and confidence fields retain
    the deterministic assessment and may therefore differ from the reconciled
    nested final assessment.
    """
    expected_summary = final_assessment_summary(report)
    if not report.summary.startswith(expected_summary):
        raise ReportIntegrityError("Report summary does not match the final assessment")
    # Stage 6 reports may have an additional deterministic observation after the
    # canonical sentence. Keep those valid history records readable, but never
    # permit that trailing prose to introduce a second final classification,
    # severity, or confidence value.
    trailing_summary = report.summary[len(expected_summary):].lower()
    classifications = {"benign", "needs_investigation", "suspicious", "confirmed"}
    classifications.discard(report.final_assessment.classification.value)
    if any(re.search(rf"\b{re.escape(value)}\b", trailing_summary) for value in classifications):
        raise ReportIntegrityError("Report summary contains a contradictory classification")
    severities = {"informational", "low", "medium", "high", "critical"}
    severities.discard(report.final_assessment.severity.value)
    if any(re.search(rf"\b{re.escape(value)}\b", trailing_summary) for value in severities):
        raise ReportIntegrityError("Report summary contains a contradictory severity")
    if re.search(r"\bconfidence\s+\d+(?:\.\d+)?", trailing_summary):
        raise ReportIntegrityError("Report summary contains a second confidence value")
    if report.automated_action != "none":
        raise ReportIntegrityError("Report requested an automated action")
    if report.missing_evidence and not report.human_review_required:
        raise ReportIntegrityError("Report removed required human review")

    evidence_ids = {item.id for item in report.evidence}
    for hypothesis in report.hypotheses:
        references = (
            hypothesis.supporting_evidence
            + hypothesis.contradicting_evidence
            + hypothesis.contextual_evidence
        )
        if not set(references) <= evidence_ids:
            raise ReportIntegrityError("Report hypothesis referenced unknown evidence")
    for relationship in report.evidence_relationships:
        if {relationship.source_evidence_id, relationship.target_evidence_id} - evidence_ids:
            raise ReportIntegrityError("Report relationship referenced unknown evidence")

    if report.llm_assessment is not None:
        try:
            validate_assessment(
                AnalystAssessment.model_validate(report.llm_assessment),
                evidence_ids,
                {item.id for item in report.hypotheses},
                report.missing_evidence,
            )
        except ValueError as exc:
            raise ReportIntegrityError("Report LLM assessment is invalid") from exc

    # An invalid consistency result is publishable only as the existing
    # fail-closed deterministic fallback, never as an LLM-derived outcome.
    if report.assessment_consistency.status.value == "invalid":
        if report.final_assessment != report.deterministic_assessment:
            raise ReportIntegrityError("Invalid consistency did not preserve deterministic fallback")
    return report
