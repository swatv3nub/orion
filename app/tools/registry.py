from __future__ import annotations

from app.config import Settings
from app.models import ToolResult
from app.tools.base import InvestigationTool, safe_error
from app.tools.mitre import MITREKnowledgeTool
from app.tools.reconix import ReconixResultsTool
from app.tools.threatlens import ThreatLensQueryTool


class ToolRegistry:
    def __init__(self, settings: Settings | None = None, tools: list[InvestigationTool] | None = None):
        configured = tools or [ThreatLensQueryTool(settings or Settings.from_env()), ReconixResultsTool(settings or Settings.from_env()), MITREKnowledgeTool()]
        self.tools = {tool.name: tool for tool in configured}

    def get(self, name: str) -> InvestigationTool | None:
        return self.tools.get(name)

    def execute(self, name: str, arguments: dict[str, str]) -> ToolResult:
        tool = self.get(name)
        if tool is None:
            return safe_error(name, "denied", "Tool is not permitted")
        try:
            return tool.execute(tool.validate(arguments))
        except Exception:
            return safe_error(name, "error", "Tool request was invalid")
