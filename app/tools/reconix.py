from __future__ import annotations

from pydantic import BaseModel, Field

from app.config import Settings
from app.models import Evidence, ToolResult
from app.tools.base import InvestigationTool
from app.tools.http import query_json


class ReconixResultsRequest(BaseModel):
    scan_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:-]+$")


class ReconixResultsTool(InvestigationTool):
    name = "reconix.results"
    description = "Retrieve results for an existing Reconix Cloud scan."
    request_model = ReconixResultsRequest

    def __init__(self, settings: Settings):
        self.settings = settings

    def execute(self, request: ReconixResultsRequest) -> ToolResult:
        result = query_json(
            self.name, self.settings.reconix_cloud_base_url, f"/api/v1/scans/{request.scan_id}/results", self.settings.reconix_cloud_api_key,
            self.settings.reconix_connect_timeout_seconds, self.settings.reconix_read_timeout_seconds,
        )
        if result.status == "success":
            result.evidence = [Evidence(
                id="pending", source="reconix_cloud", type="scan_result",
                finding="An existing Reconix scan result was returned",
                confidence=1.0, raw_reference=request.scan_id, metadata=result.data,
            )]
        return result
