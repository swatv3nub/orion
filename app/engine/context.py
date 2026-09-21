from __future__ import annotations

from app.models import Evidence, InvestigationContext, InvestigationRequest


class ContextBuilder:
    def build(self, request: InvestigationRequest, investigation_id: str) -> InvestigationContext:
        evidence: list[Evidence] = []
        evidence.append(Evidence(
            id="E-001",
            source=request.source,
            type="finding_observation",
            finding=request.finding.title,
            confidence=1.0,
            timestamp=request.timestamp,
            raw_reference=request.alert_id,
            metadata={"finding_type": request.finding.type, "severity": request.finding.severity.value},
        ))

        for key, value in request.finding.evidence.items():
            if value is None:
                continue
            evidence.append(Evidence(
                id=f"E-{len(evidence) + 1:03d}",
                source=request.source,
                type=f"{request.finding.type}_observation",
                finding=f"{key} observed: {value}",
                confidence=1.0,
                timestamp=request.timestamp,
                raw_reference=request.alert_id,
                metadata={key: value},
            ))

        return InvestigationContext(
            investigation_id=investigation_id,
            primary_alert=request,
            asset=request.asset,
            historical_alerts=request.context.historical_alerts,
            related_findings=request.context.related_findings,
            asset_inventory=request.context.asset_inventory,
            evidence=evidence,
        )
