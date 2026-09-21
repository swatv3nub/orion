from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import Hypothesis, HypothesisStatus, InvestigationContext


class HypothesisEngine:
    def generate(self, context: InvestigationContext, graph: EvidenceGraph) -> list[Hypothesis]:
        evidence_ids = [e.id for e in context.evidence]
        finding = context.primary_alert.finding
        is_http = finding.type.lower() == "http" or "http" in finding.title.lower()
        if not is_http:
            return [Hypothesis(
                id="H-001", title="Observed finding requires validation",
                description="The supplied finding is real input but its operational significance is not established.",
                supporting_evidence=evidence_ids[:1],
                missing_evidence=["Expected asset state", "Historical activity"],
                confidence=0.35, status=HypothesisStatus.unresolved,
            )]

        return [
            Hypothesis(
                id="H-001", title="Benign internet-facing service",
                description="The observed service may be intentionally exposed.",
                supporting_evidence=evidence_ids,
                missing_evidence=["Expected exposure status", "Endpoint ownership"],
                confidence=0.4, status=HypothesisStatus.plausible,
            ),
            Hypothesis(
                id="H-002", title="Administrative interface exposed",
                description="The observed endpoint may provide an administrative interface.",
                supporting_evidence=evidence_ids,
                missing_evidence=["Authentication configuration", "Expected exposure status"],
                confidence=0.5, status=HypothesisStatus.plausible,
            ),
            Hypothesis(
                id="H-003", title="Misconfigured access-control boundary",
                description="The endpoint may not enforce the access boundary intended by its owner.",
                supporting_evidence=evidence_ids,
                missing_evidence=["Authentication configuration", "Historical access activity"],
                confidence=0.35, status=HypothesisStatus.unresolved,
            ),
        ]
