from __future__ import annotations

from pydantic import BaseModel, Field

from app.models import Evidence, ToolResult
from app.tools.base import InvestigationTool


class MITRELookupRequest(BaseModel):
    technique_id: str = Field(pattern=r"^T\d{4}(?:\.\d{3})?$")


class MITREKnowledgeTool(InvestigationTool):
    name = "mitre.lookup"
    description = "Look up a technique explicitly referenced by supplied evidence."
    request_model = MITRELookupRequest

    knowledge = {
        "T1071.001": {
            "technique_id": "T1071.001", "name": "Web Protocols",
            "description": "Adversaries may communicate using application layer protocols associated with web traffic.",
            "references": [],
        }
    }

    def execute(self, request: MITRELookupRequest) -> ToolResult:
        data = self.knowledge.get(request.technique_id)
        if data is None:
            return ToolResult(tool=self.name, status="not_found", data={"technique_id": request.technique_id})
        return ToolResult(
            tool=self.name, status="success", data=data,
            evidence=[Evidence(id="pending", source="mitre", type="mitre_technique", finding=data["name"], confidence=1.0, raw_reference=request.technique_id, metadata=data)],
        )
