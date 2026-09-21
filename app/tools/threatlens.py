from __future__ import annotations

from app.config import Settings
from app.models import Evidence, ToolResult
from app.tools.base import InvestigationTool
from app.tools.http import ThreatLensQueryRequest, query_json


class ThreatLensQueryTool(InvestigationTool):
    name = "threatlens.query"
    description = "Retrieve one existing ThreatLens alert."
    request_model = ThreatLensQueryRequest

    def __init__(self, settings: Settings):
        self.settings = settings

    def execute(self, request: ThreatLensQueryRequest) -> ToolResult:
        result = query_json(
            self.name, self.settings.threatlens_base_url, f"/v1/alerts/{request.alert_id}", self.settings.threatlens_api_key,
            self.settings.threatlens_connect_timeout_seconds, self.settings.threatlens_read_timeout_seconds,
        )
        if result.status == "success":
            result.evidence = [Evidence(
                id="pending", source="threatlens", type="historical_alert",
                finding="An existing ThreatLens alert was returned",
                confidence=1.0, raw_reference=request.alert_id, metadata=result.data,
            )]
        elif result.status == "not_found":
            result.data = {"queried_alert_id": request.alert_id, "found": False}
            result.evidence = [Evidence(
                id="pending", source="threatlens", type="history_query",
                finding="ThreatLens was queried and returned no related alert",
                confidence=1.0, raw_reference=request.alert_id, metadata={"found": False},
            )]
        return result
