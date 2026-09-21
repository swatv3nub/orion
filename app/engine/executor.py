from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Callable

from app.config import MAX_RUNTIME, MAX_STEPS, Settings
from app.engine.graph import EvidenceGraph
from app.models import Evidence, InvestigationContext, InvestigationPlan, InvestigationState, ToolActivity
from app.policy import PolicyEngine
from app.tools.registry import ToolRegistry


class InvestigationExecutor:
    def __init__(self, registry: ToolRegistry, policy: PolicyEngine, settings: Settings, clock: Callable[[], float] = time.monotonic):
        self.registry = registry
        self.policy = policy
        self.settings = settings
        self.clock = clock

    def execute(self, context: InvestigationContext, graph: EvidenceGraph, plan: InvestigationPlan) -> tuple[InvestigationState, list[ToolActivity]]:
        state = InvestigationState(investigation_id=context.investigation_id, status="investigating", evidence_count=len(context.evidence))
        activities: list[ToolActivity] = []
        started = self.clock()
        failures = False
        for step in plan.steps[:min(self.settings.max_investigation_steps, MAX_STEPS)]:
            state.current_step = step.step_id
            if self.clock() - started >= min(self.settings.max_runtime_seconds, MAX_RUNTIME):
                state.status, state.timeout, state.stop_reason = "timeout", True, "timeout"
                break
            decision = self.policy.check(step, state, started)
            if not decision.allowed:
                state.policy_denials.append(f"{step.step_id}: {decision.reason}")
                if "runtime" in decision.reason:
                    state.status, state.timeout, state.stop_reason = "timeout", True, "timeout"
                    break
                if "tool-call" in decision.reason:
                    state.stop_reason = "max_tool_calls"
                    break
                continue
            call_started = self.clock()
            state.tool_calls += 1
            result = self.registry.execute(step.tool, step.arguments)
            failures = failures or result.status not in {"success", "not_found"}
            added = 0
            for evidence in result.evidence:
                evidence.id = f"{context.investigation_id}:E-{len(context.evidence) + 1:03d}"
                context.evidence.append(evidence)
                graph.add_node(evidence.id, "evidence", evidence.model_dump(mode="json"))
                added += 1
            state.completed_steps += 1
            state.evidence_count = len(context.evidence)
            activities.append(ToolActivity(step_id=step.step_id, tool=step.tool, status=result.status, duration_ms=int((self.clock() - call_started) * 1000), evidence_added=added))
            if self.clock() - started >= min(self.settings.max_runtime_seconds, MAX_RUNTIME):
                state.status, state.timeout, state.stop_reason = "timeout", True, "timeout"
                break
        if state.stop_reason is None:
            state.stop_reason = "tool_failure" if failures else ("no_missing_evidence" if not plan.steps else "completed")
            state.status = "partial" if failures else "completed"
        if state.status == "investigating":
            state.status = "partial"
        state.current_step = None
        state.completed_at = datetime.now(timezone.utc)
        return state, activities
