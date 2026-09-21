from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from app.models import ToolResult


class InvestigationTool(ABC):
    name: str
    description: str
    request_model: type[BaseModel]

    @abstractmethod
    def execute(self, request: BaseModel) -> ToolResult:
        raise NotImplementedError

    def validate(self, arguments: dict[str, str]) -> BaseModel:
        return self.request_model.model_validate(arguments)


def safe_error(tool: str, status: str, message: str) -> ToolResult:
    return ToolResult(tool=tool, status=status, error=message)
