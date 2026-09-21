from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import AnalystReport, Evaluation, Hypothesis, InvestigationContext


class ReportGenerator:
    def generate(self, context: InvestigationContext, graph: EvidenceGraph,
                 hypotheses: list[Hypothesis], evaluation: Evaluation) -> AnalystReport:
        title = context.primary_alert.finding.title
        return AnalystReport(
            investigation_id=context.investigation_id,
            alert_id=context.primary_alert.alert_id,
            classification=evaluation.classification,
            severity=context.primary_alert.finding.severity,
            confidence=evaluation.confidence,
            summary=f"{title} requires additional investigation because the available evidence does not establish whether the exposure is intentional.",
            hypotheses=hypotheses,
            evidence=context.evidence,
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
        )
