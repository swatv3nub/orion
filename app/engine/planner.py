from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import InvestigationContext, InvestigationPlan, InvestigationStep, MissingEvidence, Hypothesis


class InvestigationPlanner:
    def plan(self, context: InvestigationContext, graph: EvidenceGraph, hypotheses: list[Hypothesis], missing: list[MissingEvidence]) -> InvestigationPlan:
        steps: list[InvestigationStep] = []
        for item in missing:
            if not item.possible_sources:
                continue
            tool = item.possible_sources[0]
            arguments: dict[str, str] = {}
            if tool == "threatlens.query":
                arguments = {"alert_id": context.primary_alert.alert_id}
                purpose = "Check for related historical alerts"
            elif tool == "reconix.results" and context.scan_id:
                arguments = {"scan_id": context.scan_id}
                purpose = "Retrieve existing Reconix evidence"
            elif tool == "mitre.lookup" and context.primary_alert.mitre_attack:
                arguments = {"technique_id": context.primary_alert.mitre_attack[0]}
                purpose = "Look up an explicitly referenced MITRE technique"
            else:
                continue
            steps.append(InvestigationStep(
                step_id=f"STEP-{len(steps) + 1:03d}", tool=tool, purpose=purpose,
                reason=f"{item.description} is currently unavailable", priority=len(steps) + 1,
            arguments=arguments))
        return InvestigationPlan(investigation_id=context.investigation_id, steps=steps[:5])
