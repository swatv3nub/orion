from __future__ import annotations

from app.models import Evidence, InvestigationContext, InvestigationRequest


class ContextBuilder:
    def build(self, request: InvestigationRequest, investigation_id: str) -> InvestigationContext:
        evidence: list[Evidence] = []
        identifiers = {
            key: value
            for key in ("scan_id", "finding_id")
            for value in self._values(request.finding.evidence, key)
            if value
        }
        def evidence_id() -> str:
            return f"{investigation_id}:E-{len(evidence) + 1:03d}"
        finding_data = dict(request.finding.evidence)
        asset = request.asset.hostname if request.asset and request.asset.hostname else request.asset.ip if request.asset else None
        if asset:
            finding_data.setdefault("hostname", asset)
        evidence.append(Evidence(
            id=evidence_id(),
            source=request.source,
            type="finding_observation",
            finding=self._finding_text(request.finding.title, finding_data, asset),
            confidence=1.0,
            timestamp=request.timestamp,
            raw_reference=request.alert_id,
            metadata={"observation_type": request.finding.type.lower(), "severity": request.finding.severity.value, **finding_data, **identifiers},
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

    def _values(self, value: object, wanted: str) -> list[str]:
        if isinstance(value, dict):
            found: list[str] = []
            for key, item in value.items():
                if key == wanted and isinstance(item, (str, int)):
                    found.append(str(item))
                found.extend(self._values(item, wanted))
            return found
        if isinstance(value, list):
            return [item for nested in value for item in self._values(nested, wanted)]
        return []

    def _finding_text(self, title: str, evidence: dict[str, object], asset: str | None) -> str:
        if "port" in evidence:
            return f"{asset or 'Asset'} has port {evidence['port']} open"
        if "status" in evidence and "url" in evidence:
            return f"{evidence['url']} returned HTTP {evidence['status']}"
        return title
