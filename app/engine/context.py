from __future__ import annotations

from app.models import Evidence, InvestigationContext, InvestigationRequest


class ContextBuilder:
    def build(self, request: InvestigationRequest, investigation_id: str) -> InvestigationContext:
        evidence: list[Evidence] = []
        def evidence_id() -> str:
            return f"{investigation_id}:E-{len(evidence) + 1:03d}"
        evidence.append(Evidence(
            id=evidence_id(),
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
                id=evidence_id(),
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
            scan_id=request.context.model_extra.get("scan_id") if request.context.model_extra else request.finding.evidence.get("scan_id"),
            evidence=evidence,
        )
