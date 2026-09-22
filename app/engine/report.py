from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import AnalystReport, CorrelationResult, Evaluation, Hypothesis, InvestigationContext, InvestigationState, ToolActivity


class ReportGenerator:
    def generate(self, context: InvestigationContext, graph: EvidenceGraph,
                  hypotheses: list[Hypothesis], evaluation: Evaluation,
                  activities: list[ToolActivity] | None = None,
                  state: InvestigationState | None = None,
                  correlation: CorrelationResult | None = None) -> AnalystReport:
        title = context.primary_alert.finding.title
        return AnalystReport(
            investigation_id=context.investigation_id,
            alert_id=context.primary_alert.alert_id,
            classification=evaluation.classification,
            severity=context.primary_alert.finding.severity,
            confidence=evaluation.confidence,
            summary=hypotheses[0].description if hypotheses else f"{title} requires additional investigation.",
            hypotheses=hypotheses,
            evidence=context.evidence,
            evidence_relationships=correlation.relationships if correlation else [],
            raw_evidence_count=correlation.raw_evidence_count if correlation else len(context.evidence),
            canonical_evidence_count=correlation.canonical_evidence_count if correlation else len(context.evidence),
            correlated_evidence_count=correlation.correlated_evidence_count if correlation else len(context.evidence),
            semantic_relationship_count=correlation.semantic_relationship_count if correlation else 0,
            provenance_relationship_count=correlation.provenance_relationship_count if correlation else 0,
            missing_evidence=evaluation.missing_evidence,
            investigation_steps=self._steps(evaluation.missing_evidence),
            mitre_attack=context.primary_alert.mitre_attack,
            recommended_actions=["Review the evidence with a human analyst."],
            uncertainties=evaluation.uncertainties,
            human_review_required=evaluation.needs_investigation,
            automated_action="none",
            tool_activity=activities or [],
            stop_reason=state.stop_reason if state else None,
            state=state,
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
