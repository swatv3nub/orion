from __future__ import annotations

from pydantic import BaseModel

from app.config import Settings
from app.engine.context import ContextBuilder
from app.engine.executor import InvestigationExecutor
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.missing import MissingEvidenceAnalyzer
from app.engine.planner import InvestigationPlanner
from app.models import Evidence, InvestigationPlan, InvestigationRequest, ToolResult
from app.policy import PolicyEngine
from app.service import InvestigationService
from app.tools.base import InvestigationTool
from app.tools.registry import ToolRegistry
from app.tools.reconix import ReconixResultsRequest
from app.tools.threatlens import ThreatLensQueryRequest

from tests.test_stage1 import ALERT


class FakeThreatLens(InvestigationTool):
    name = "threatlens.query"
    description = "test"
    request_model = ThreatLensQueryRequest

    def execute(self, request: BaseModel) -> ToolResult:
        return ToolResult(tool=self.name, status="not_found", evidence=[Evidence(
            id="pending", source="threatlens", type="history_query",
            finding="ThreatLens was queried and returned no related alert",
            confidence=1.0, raw_reference=request.alert_id,
        )])


class FakeReconix(InvestigationTool):
    name = "reconix.results"
    description = "test"
    request_model = ReconixResultsRequest

    def execute(self, request: BaseModel) -> ToolResult:
        return ToolResult(tool=self.name, status="success", evidence=[Evidence(
            id="pending", source="reconix_cloud", type="scan_result",
            finding="Port 443 observed", confidence=1.0, raw_reference=request.scan_id,
        )])


class FakeIntentionalHistory(FakeThreatLens):
    def execute(self, request: BaseModel) -> ToolResult:
        return ToolResult(tool=self.name, status="success", evidence=[Evidence(
            id="pending", source="threatlens", type="historical_alert",
            finding="The endpoint is intentionally protected and monitored",
            confidence=1.0, raw_reference=request.alert_id, metadata={"intentional": True},
        )])


def test_planner_uses_only_registered_tools_and_history_query_is_distinguished():
    request = InvestigationRequest.model_validate(ALERT)
    context = ContextBuilder().build(request, "INV-stage2")
    graph = build_graph(context)
    hypotheses = HypothesisEngine().generate(context, graph)
    missing = MissingEvidenceAnalyzer().analyze(context, graph, hypotheses)
    plan = InvestigationPlanner().plan(context, graph, hypotheses, missing)
    assert [step.tool for step in plan.steps] == ["threatlens.query"]
    assert all(step.tool in {"threatlens.query", "reconix.results", "mitre.lookup"} for step in plan.steps)

    service = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens()]))
    report = service.investigate(request)
    assert any(e.type == "history_query" for e in report.evidence)
    assert "Historical alerts for this asset" not in report.missing_evidence
    assert report.tool_activity[0].tool == "threatlens.query"


def test_reconix_results_become_evidence_and_hypotheses_are_rerun():
    payload = {**ALERT, "context": {**ALERT["context"], "scan_id": "scan_demo_001"}}
    service = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeThreatLens(), FakeReconix()]))
    report = service.investigate(InvestigationRequest.model_validate(payload))
    assert any(e.type == "scan_result" for e in report.evidence)
    assert any(activity.tool == "reconix.results" for activity in report.tool_activity)
    assert report.state.evidence_count == len(report.evidence)


def test_mitre_lookup_uses_only_explicit_mapping():
    registry = ToolRegistry()
    assert registry.execute("mitre.lookup", {"technique_id": "T1071.001"}).status == "success"
    assert registry.execute("mitre.lookup", {"technique_id": "T9999"}).status == "not_found"


def test_new_evidence_changes_hypothesis_evaluation():
    request = InvestigationRequest.model_validate({**ALERT, "mitre_attack": []})
    before = HypothesisEngine().generate(ContextBuilder().build(request, "INV-before"), build_graph(ContextBuilder().build(request, "INV-before")))
    service = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeIntentionalHistory()]))
    report = service.investigate(request)
    before_admin = next(h for h in before if h.id == "H-002")
    after_admin = next(h for h in report.hypotheses if h.id == "H-002")
    assert after_admin.confidence < before_admin.confidence


def test_registry_and_policy_fail_closed():
    registry = ToolRegistry(settings=Settings())
    assert registry.get("shell.execute") is None
    assert registry.execute("shell.execute", {"command": "whoami"}).status == "denied"


def test_limits_and_timeout_are_enforced_without_sleeping():
    settings = Settings(max_investigation_steps=99, max_tool_calls=99, max_runtime_seconds=60)
    registry = ToolRegistry(tools=[FakeThreatLens()])
    clock_values = iter([0.0, 0.0, 61.0])
    clock = lambda: next(clock_values, 61.0)
    executor = InvestigationExecutor(registry, PolicyEngine(settings, registry, clock), settings, clock)
    request = InvestigationRequest.model_validate(ALERT)
    context = ContextBuilder().build(request, "INV-timeout")
    graph = build_graph(context)
    plan = InvestigationPlan(investigation_id=context.investigation_id, steps=[
        {"step_id": f"STEP-{i:03d}", "tool": "threatlens.query", "purpose": "x", "reason": "x", "priority": i, "arguments": {"alert_id": request.alert_id}}
        for i in range(1, 10)
    ])
    state, _ = executor.execute(context, graph, plan)
    assert state.status == "timeout"
    assert state.stop_reason == "timeout"
    assert state.tool_calls == 0
