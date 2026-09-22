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
            correlated_evidence_count=correlation.correlated_evidence_count if correlation else len(context.evidence),
            missing_evidence=evaluation.missing_evidence,
            investigation_steps=[
                "Verify whether the endpoint is intentionally public.",
                "Inspect authentication configuration.",
                "Review historical access logs.",
            ],
            mitre_attack=context.primary_alert.mitre_attack,
            recommended_actions=["Review the evidence with a human analyst."],
            uncertainties=evaluation.uncertainties,
            human_review_required=evaluation.needs_investigation,
            automated_action="none",
            tool_activity=activities or [],
            stop_reason=state.stop_reason if state else None,
            state=state,
        )
