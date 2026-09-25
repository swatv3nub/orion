from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import AnalystReport, AssessmentConsistency, CorrelationResult, Evaluation, FinalAssessment, Hypothesis, InvestigationContext, InvestigationState, Severity, ToolActivity
from app.engine.assessment import reconcile_assessment
from app.engine.report_validation import validate_report_integrity
from app.llm.schemas import AnalystAssessment, validate_assessment


class ReportGenerator:
    def generate(self, context: InvestigationContext, graph: EvidenceGraph,
                  hypotheses: list[Hypothesis], evaluation: Evaluation,
                  activities: list[ToolActivity] | None = None,
                  state: InvestigationState | None = None,
                  correlation: CorrelationResult | None = None,
                  llm_assessment: dict | None = None,
                  llm_status: str | None = None,
                  llm_model: str | None = None,
                  llm_failure_reason: str | None = None,
                  llm_provider: str | None = None,
                  llm_fallback_used: bool = False,
                  llm_primary_failure_reason: str | None = None,
                  deterministic_assessment: FinalAssessment | None = None,
                  final_assessment: FinalAssessment | None = None,
                  assessment_consistency: AssessmentConsistency | None = None) -> AnalystReport:
        validated_llm_assessment = None
        if llm_assessment is not None:
            # The service validates before calling the report generator. Retain this
            # check here as well because this class is also used directly in tests
            # and by internal callers. An unvalidated LLM assessment must never be
            # rendered as report data.
            validated_llm_assessment = validate_assessment(
                AnalystAssessment.model_validate(llm_assessment),
                {item.id for item in context.evidence},
                {item.id for item in hypotheses},
                evaluation.missing_evidence,
            )
        if deterministic_assessment is None or final_assessment is None or assessment_consistency is None:
            deterministic_assessment, final_assessment, assessment_consistency = reconcile_assessment(
                validated_llm_assessment,
                evaluation,
                context.primary_alert.finding.severity,
                hypotheses,
            )
        report = AnalystReport(
            investigation_id=context.investigation_id,
            alert_id=context.primary_alert.alert_id,
            classification=evaluation.classification,
            severity=context.primary_alert.finding.severity,
            confidence=evaluation.confidence,
            summary=self._summary(final_assessment),
            hypotheses=hypotheses,
            evidence=context.evidence,
            evidence_relationships=correlation.relationships if correlation else [],
            raw_evidence_count=correlation.raw_evidence_count if correlation else len(context.evidence),
            canonical_evidence_count=correlation.canonical_evidence_count if correlation else len(context.evidence),
            correlated_evidence_count=correlation.correlated_evidence_count if correlation else len(context.evidence),
            semantic_relationship_count=correlation.semantic_relationship_count if correlation else 0,
            provenance_relationship_count=correlation.provenance_relationship_count if correlation else 0,
            # Keep the validated LLM response separate from the deterministic
            # hypotheses and the authoritative reconciled final assessment.
            llm_assessment=validated_llm_assessment.model_dump(mode="json") if validated_llm_assessment else None,
            deterministic_assessment=deterministic_assessment,
            final_assessment=final_assessment,
            assessment_consistency=assessment_consistency,
            llm_status=llm_status,
            llm_model=llm_model,
            llm_failure_reason=llm_failure_reason,
            llm_provider=llm_provider,
            llm_fallback_used=llm_fallback_used,
            llm_primary_failure_reason=llm_primary_failure_reason,
            missing_evidence=evaluation.missing_evidence,
            investigation_steps=self._steps(evaluation.missing_evidence),
            mitre_attack=context.primary_alert.mitre_attack,
            recommended_actions=["Review the evidence with a human analyst."],
            uncertainties=evaluation.uncertainties,
            # Missing evidence is independently sufficient to require review,
            # even if a future evaluator changes its review flag.
            human_review_required=evaluation.needs_investigation or bool(evaluation.missing_evidence),
            automated_action="none",
            tool_activity=activities or [],
            stop_reason=state.stop_reason if state else None,
            state=state,
        )
        return validate_report_integrity(report)

    def _summary(self, final_assessment: FinalAssessment) -> str:
        """Build a deterministic presentation summary from authoritative report data.

        This deliberately does not copy the LLM summary. The LLM's separately
        inspectable, evidence-validated summary remains in ``llm_assessment``.
        """
        return (
            f"Final assessment: {final_assessment.classification} "
            f"({final_assessment.severity}, confidence {final_assessment.confidence:.2f}). "
            "Review the evidence, hypotheses, and missing evidence in this report."
        )

    def _steps(self, missing: list[str]) -> list[str]:
        rules = {
            "Expected exposure status": "Verify whether the service is intentionally exposed.",
            "Service ownership": "Confirm service ownership and expected operating context.",
            "Authentication and access-control configuration": "Review the authentication and access-control configuration.",
            "Historical access activity": "Review historical access logs for unexpected access patterns.",
            "Cloud resource ownership": "Confirm cloud resource ownership.",
            "Cloud access-control configuration": "Review cloud access-control configuration.",
            "Intended public or private state": "Verify the intended public or private state of the cloud resource.",
        }
        return [rules[item] for item in missing if item in rules]
