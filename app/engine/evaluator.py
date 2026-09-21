from __future__ import annotations

from app.models import Classification, Evaluation, Hypothesis, InvestigationContext


class EvidenceEvaluator:
    def evaluate(self, context: InvestigationContext, hypotheses: list[Hypothesis]) -> Evaluation:
        missing = list(dict.fromkeys(item for hypothesis in hypotheses for item in hypothesis.missing_evidence))
        average = sum(h.confidence for h in hypotheses) / len(hypotheses) if hypotheses else 0.0
        contradictions = sum(len(h.contradicting_evidence) for h in hypotheses)
        confidence = max(0.0, min(1.0, average - min(0.3, len(missing) * 0.03) - min(0.4, contradictions * 0.1)))
        uncertainties = ["Confidence is heuristic and evidence is limited to supplied input."]
        if not context.historical_alerts:
            uncertainties.append("Historical activity unavailable.")
        return Evaluation(
            classification=Classification.needs_investigation,
            confidence=confidence,
            missing_evidence=missing,
            uncertainties=uncertainties,
            needs_investigation=True,
        )
