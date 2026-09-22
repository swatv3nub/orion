from __future__ import annotations

from app.engine.graph import EvidenceGraph
from app.models import CorrelationResult, Evidence, Hypothesis, HypothesisStatus, InvestigationContext


class HypothesisEngine:
    def generate(self, context: InvestigationContext, graph: EvidenceGraph, correlation: CorrelationResult | None = None) -> list[Hypothesis]:
        evidence_by_id = {e.id: e for e in context.evidence}
        evidence_ids = correlation.unique_evidence_ids if correlation else list(evidence_by_id)
        evidence = [evidence_by_id[evidence_id] for evidence_id in evidence_ids if evidence_id in evidence_by_id]
        finding = context.primary_alert.finding
        history_checked = any(e.type in {"historical_alert", "history_query"} for e in context.evidence)
        intentionally_protected = any(
            "intentional" in e.finding.lower() or e.metadata.get("intentional") is True
            for e in context.evidence
        )
        is_http = finding.type.lower() == "http" or "http" in finding.title.lower()
        if not is_http:
            supporting, contradicting, contextual = self._evidence_roles(evidence, "H-001", correlation, primary_only=True)
            return [Hypothesis(
                id="H-001", title="Observed finding requires validation",
                description="The supplied finding is real input but its operational significance is not established.",
                supporting_evidence=supporting or evidence_ids[:1],
                contradicting_evidence=contradicting,
                contextual_evidence=contextual,
                missing_evidence=[] if history_checked else ["Expected asset state", "Historical activity"],
                confidence=self._confidence(0.35, supporting, contradicting, []), status=HypothesisStatus.unresolved,
            )]

        observations = self._observation_summary(evidence[1:])
        context_description = (
            f" Correlated observations include {', '.join(observations)}."
            " They provide service context but do not establish unintended exposure or vulnerability."
            if observations else ""
        )
        roles = {
            "H-001": self._evidence_roles(evidence, "H-001", correlation),
            "H-002": self._evidence_roles(evidence, "H-002", correlation),
            "H-003": self._evidence_roles(evidence, "H-003", correlation),
        }
        h1_support, h1_contradicting, h1_contextual = roles["H-001"]
        h2_support, h2_contradicting, h2_contextual = roles["H-002"]
        h3_support, h3_contradicting, h3_contextual = roles["H-003"]
        return [
            Hypothesis(
                id="H-001", title="Benign internet-facing service",
                description="The observed service may be intentionally exposed." + context_description,
                supporting_evidence=h1_support,
                contradicting_evidence=h1_contradicting,
                contextual_evidence=h1_contextual,
                missing_evidence=["Expected exposure status", "Endpoint ownership"],
                confidence=self._confidence(0.4, h1_support, h1_contradicting, ["Expected exposure status", "Endpoint ownership"], correlation),
                status=HypothesisStatus.plausible,
            ),
            Hypothesis(
                id="H-002", title="Administrative interface exposed",
                description="The observed endpoint may provide an administrative interface." + context_description,
                supporting_evidence=h2_support,
                contradicting_evidence=h2_contradicting,
                contextual_evidence=h2_contextual,
                missing_evidence=["Authentication configuration", "Expected exposure status"],
                confidence=self._confidence(0.2 if intentionally_protected else 0.5, h2_support, h2_contradicting, ["Authentication configuration", "Expected exposure status"], correlation),
                status=HypothesisStatus.plausible,
            ),
            Hypothesis(
                id="H-003", title="Misconfigured access-control boundary",
                description="The endpoint may not enforce the access boundary intended by its owner." + context_description,
                supporting_evidence=h3_support,
                contradicting_evidence=h3_contradicting,
                contextual_evidence=h3_contextual,
                missing_evidence=["Authentication configuration"] if history_checked else ["Authentication configuration", "Historical access activity"],
                confidence=self._confidence(0.35, h3_support, h3_contradicting, ["Authentication configuration"] if history_checked else ["Authentication configuration", "Historical access activity"], correlation),
                status=HypothesisStatus.unresolved,
            ),
        ]

    def _evidence_roles(self, evidence: list[Evidence], hypothesis_id: str, correlation: CorrelationResult | None, primary_only: bool = False) -> tuple[list[str], list[str], list[str]]:
        if correlation is None:
            supporting = [evidence[0].id] if evidence else []
            return (supporting if primary_only else [e.id for e in evidence], [], [])
        supporting: list[str] = []
        contradicting: list[str] = []
        contextual: list[str] = []
        for index, item in enumerate(evidence):
            if self._contradicts(item, hypothesis_id):
                contradicting.append(item.id)
            elif self._supports(item, hypothesis_id) or index == 0:
                supporting.append(item.id)
            else:
                contextual.append(item.id)
        return supporting, contradicting, contextual

    def _supports(self, evidence: Evidence, hypothesis_id: str) -> bool:
        value = evidence.metadata.get("supports")
        if value is True:
            return True
        if isinstance(value, str):
            return value in {hypothesis_id, "all"}
        if isinstance(value, list):
            return hypothesis_id in value or "all" in value
        if hypothesis_id == "H-002":
            text = evidence.finding.lower()
            return any(term in text for term in ("admin", "authentication", "unauthorized", "401"))
        return False

    def _contradicts(self, evidence: Evidence, hypothesis_id: str) -> bool:
        value = evidence.metadata.get("contradicts")
        if value is True:
            return True
        if isinstance(value, str):
            return value in {hypothesis_id, "all"}
        return isinstance(value, list) and (hypothesis_id in value or "all" in value)

    def _confidence(self, base: float, supporting: list[str], contradicting: list[str], missing: list[str], correlation: CorrelationResult | None = None) -> float:
        # Bounded heuristic: support adds at most .15, relations at most .05,
        # while explicit contradictions and unresolved requirements subtract.
        value = base + min(0.15, len(set(supporting)) * 0.05)
        if correlation and any(relation.relationship_type in {"related_service", "related_dns", "related_tls", "related_http"} for relation in correlation.relationships):
            value += 0.05
        value -= min(0.4, len(set(contradicting)) * 0.15)
        value -= min(0.3, len(missing) * 0.03)
        return max(0.0, min(1.0, value))

    def _observation_summary(self, evidence: list[Evidence]) -> list[str]:
        summaries: list[str] = []
        for item in evidence:
            metadata = item.metadata
            if "port" in metadata:
                label = f"port {metadata['port']}"
            elif item.type.endswith("dns_observation"):
                label = "DNS resolution"
            elif item.type.endswith("tls_observation"):
                label = "TLS information"
            elif item.type.endswith("http_observation"):
                label = f"HTTP response {metadata.get('status', metadata.get('status_code', 'data'))}"
            elif item.type.endswith("subdomain_observation"):
                label = f"subdomain {metadata.get('hostname', metadata.get('value', 'observed'))}"
            elif item.type.endswith("cloud_observation"):
                label = "cloud observations"
            else:
                continue
            if label not in summaries:
                summaries.append(label)
        return summaries
