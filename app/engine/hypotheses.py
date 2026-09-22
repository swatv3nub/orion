from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import CorrelationResult, Evidence, Hypothesis, HypothesisStatus, InvestigationContext


class HypothesisEngine:
    def generate(self, context: InvestigationContext, graph: EvidenceGraph, correlation: CorrelationResult | None = None) -> list[Hypothesis]:
        evidence = {item.id: item for item in context.evidence}
        ids = correlation.unique_evidence_ids if correlation else list(evidence)
        atomic = [evidence[item] for item in ids if item in evidence]
        by_category: dict[str, list[Evidence]] = {}
        for item in atomic:
            category = self._category(item)
            by_category.setdefault(category, []).append(item)

        services = by_category.get("port", []) + by_category.get("http", [])
        if services:
            support = [item.id for item in services]
            context_ids = [item.id for category in ("dns", "tls", "subdomain") for item in by_category.get(category, [])]
            missing = ["Expected exposure status", "Service ownership", "Authentication and access-control configuration", "Historical access activity"]
            hypotheses = [Hypothesis(
                id="H-001",
                title="Internet-facing web service requires validation",
                description=self._service_description(context, by_category),
                supporting_evidence=support,
                contextual_evidence=context_ids,
                contradicting_evidence=self._contradictions(atomic, "H-001"),
                missing_evidence=missing,
                confidence=self._confidence(0.35, support, atomic, missing, correlation),
                status=HypothesisStatus.plausible,
            )]
            if "admin" in context.primary_alert.finding.title.lower():
                hypotheses.append(Hypothesis(
                    id="H-002", title="Administrative interface exposure requires validation",
                    description="An administrative endpoint is identified, but its intended exposure and access controls are not established.",
                    supporting_evidence=[atomic[0].id] if atomic else [],
                    missing_evidence=["Authentication and access-control configuration", "Expected exposure status"],
                    confidence=0.3 if any("intentional" in item.finding.lower() or item.metadata.get("intentional") is True for item in context.evidence) else 0.4,
                    status=HypothesisStatus.plausible,
                ))
            return hypotheses + self._cloud_hypothesis(by_category, atomic, correlation)

        cloud = by_category.get("cloud", [])
        if cloud:
            missing = ["Cloud resource ownership", "Cloud access-control configuration", "Intended public or private state"]
            return [Hypothesis(
                id="H-004", title="Cloud resource exposure requires validation",
                description="Cloud resource observations were returned, but their intended access state is not established.",
                supporting_evidence=[item.id for item in cloud],
                missing_evidence=missing,
                contradicting_evidence=self._contradictions(atomic, "H-004"),
                confidence=self._confidence(0.3, [item.id for item in cloud], atomic, missing, correlation, "H-004", support_cap=0.08),
                status=HypothesisStatus.unresolved,
            )]
        return [Hypothesis(
            id="H-001", title="Observed finding requires validation",
            description="The supplied finding is real input but its operational significance is not established.",
            supporting_evidence=[atomic[0].id] if atomic else [],
            contradicting_evidence=self._contradictions(context.evidence, "H-001"),
            missing_evidence=["Expected asset state", "Historical activity"],
            confidence=0.3,
            status=HypothesisStatus.unresolved,
        )]

    def _cloud_hypothesis(self, categories: dict[str, list[Evidence]], evidence: list[Evidence], correlation: CorrelationResult | None) -> list[Hypothesis]:
        cloud = categories.get("cloud", [])
        if not cloud:
            return []
        missing = ["Cloud resource ownership", "Cloud access-control configuration", "Intended public or private state"]
        return [Hypothesis(
            id="H-004", title="Cloud resource exposure requires validation",
            description="Cloud observations provide context but do not establish intended access state or a vulnerability.",
            supporting_evidence=[item.id for item in cloud],
            missing_evidence=missing,
            contradicting_evidence=self._contradictions(evidence, "H-004"),
            confidence=self._confidence(0.25, [item.id for item in cloud], evidence, missing, correlation, "H-004", support_cap=0.08),
            status=HypothesisStatus.unresolved,
        )]

    def _category(self, evidence: Evidence) -> str:
        value = evidence.metadata.get("observation_type")
        return str(value).lower() if value else "observation"

    def _service_description(self, context: InvestigationContext, categories: dict[str, list[Evidence]]) -> str:
        asset = context.asset.hostname if context.asset and context.asset.hostname else "the asset"
        parts: list[str] = []
        if categories.get("port"):
            parts.append("open ports " + ", ".join(str(item.metadata.get("port")) for item in categories["port"] if item.metadata.get("port") is not None))
        if categories.get("http"):
            parts.append("HTTP response data")
        return f"The scan confirms an externally reachable web service on {asset} through {' and '.join(parts)}. Available evidence establishes exposure, but not intended exposure, access-control posture, or vulnerability."

    def _contradictions(self, evidence: list[Evidence], hypothesis: str) -> list[str]:
        return [item.id for item in evidence if item.metadata.get("contradicts") is True or isinstance(item.metadata.get("contradicts"), list) and hypothesis in item.metadata["contradicts"]]

    def _confidence(self, base: float, support: list[str], evidence: list[Evidence], missing: list[str], correlation: CorrelationResult | None, hypothesis: str = "H-001", support_cap: float = 0.24) -> float:
        contradictions = self._contradictions(evidence, hypothesis)
        value = base + min(support_cap, len(set(support)) * 0.08)
        if correlation and any(item.relationship_type == "corroborates" for item in correlation.relationships):
            value += 0.08
        value -= min(0.3, len(contradictions) * 0.15)
        value -= min(0.24, len(missing) * 0.06)
        return max(0.0, min(1.0, value))
