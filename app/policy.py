from __future__ import annotations

import time

from app.config import MAX_CALLS, MAX_RUNTIME, MAX_STEPS, Settings
from app.models import InvestigationState, InvestigationStep
from app.tools.registry import ToolRegistry


class PolicyDecision:
    def __init__(self, allowed: bool, reason: str):
        self.allowed = allowed
        self.reason = reason


class PolicyEngine:
    def __init__(self, settings: Settings, registry: ToolRegistry, clock=time.monotonic):
        self.settings = settings
        self.registry = registry
        self.clock = clock

    def check(self, step: InvestigationStep, state: InvestigationState, started: float) -> PolicyDecision:
        if self.registry.get(step.tool) is None:
            return PolicyDecision(False, "Tool is not permitted")
        if state.completed_steps >= min(self.settings.max_investigation_steps, MAX_STEPS):
            return PolicyDecision(False, "Investigation step limit reached")
        if state.tool_calls >= min(self.settings.max_tool_calls, MAX_CALLS):
            return PolicyDecision(False, "Investigation tool-call limit reached")
        if self.clock() - started >= min(self.settings.max_runtime_seconds, MAX_RUNTIME):
            return PolicyDecision(False, "Investigation runtime limit reached")
        if step.requires_human_approval:
            return PolicyDecision(False, "Human approval is required")
        try:
            self.registry.get(step.tool).validate(step.arguments)  # type: ignore[union-attr]
        except Exception:
            return PolicyDecision(False, "Tool arguments are invalid")
        return PolicyDecision(True, "Tool is registered and request is within investigation limits")
