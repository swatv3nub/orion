from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import InvestigationContext, MissingEvidence, Hypothesis


class MissingEvidenceAnalyzer:
    def analyze(self, context: InvestigationContext, graph: EvidenceGraph, hypotheses: list[Hypothesis]) -> list[MissingEvidence]:
        missing: list[MissingEvidence] = []
        types = {e.type for e in context.evidence}
        if "historical_alert" not in types and "history_query" not in types:
            missing.append(MissingEvidence(id="M-001", description="Historical alerts for this asset", importance="high", possible_sources=["threatlens.query"]))
        if context.scan_id and "scan_result" not in types:
            missing.append(MissingEvidence(id="M-002", description="Existing Reconix scan results", importance="medium", possible_sources=["reconix.results"]))
        if context.primary_alert.mitre_attack and "mitre_technique" not in types:
            missing.append(MissingEvidence(id="M-003", description="Referenced MITRE technique details", importance="low", possible_sources=["mitre.lookup"]))
        return missing
