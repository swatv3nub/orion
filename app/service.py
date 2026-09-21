from __future__ import annotations

from uuid import uuid4

from app.config import Settings
from app.integrations.threatlens import ThreatLensClient, ThreatLensAlertResponse
from app.engine.context import ContextBuilder
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.executor import InvestigationExecutor
from app.engine.missing import MissingEvidenceAnalyzer
from app.engine.planner import InvestigationPlanner
from app.engine.report import ReportGenerator
from app.policy import PolicyEngine
from app.models import AnalystReport, InvestigationRequest
from app.tools.registry import ToolRegistry


class InvestigationService:
    def __init__(self, settings: Settings | None = None, registry: ToolRegistry | None = None, threatlens_client: ThreatLensClient | None = None) -> None:
        settings = settings or Settings.from_env()
        registry = registry or ToolRegistry(settings)
        self.threatlens_client = threatlens_client or ThreatLensClient(settings)
        self.context_builder = ContextBuilder()
        self.hypothesis_engine = HypothesisEngine()
        self.evaluator = EvidenceEvaluator()
        self.missing_analyzer = MissingEvidenceAnalyzer()
        self.planner = InvestigationPlanner()
        self.executor = InvestigationExecutor(registry, PolicyEngine(settings, registry), settings)
        self.report_generator = ReportGenerator()
        self.reports: dict[str, AnalystReport] = {}

    def investigate(self, request: InvestigationRequest) -> AnalystReport:
        investigation_id = f"INV-{uuid4().hex[:12]}"
        context = self.context_builder.build(request, investigation_id)
        graph = build_graph(context)
        hypotheses = self.hypothesis_engine.generate(context, graph)
        for hypothesis in hypotheses:
            graph.add_node(hypothesis.id, "hypothesis", hypothesis.model_dump(mode="json"))
        missing = self.missing_analyzer.analyze(context, graph, hypotheses)
        plan = self.planner.plan(context, graph, hypotheses, missing)
        state, activities = self.executor.execute(context, graph, plan)
        hypotheses = self.hypothesis_engine.generate(context, graph)
        for hypothesis in hypotheses:
            graph.add_node(hypothesis.id, "hypothesis", hypothesis.model_dump(mode="json"))
        evaluation = self.evaluator.evaluate(context, hypotheses)
        evaluation.missing_evidence = [item.description for item in self.missing_analyzer.analyze(context, graph, hypotheses)]
        if state.timeout:
            evaluation.uncertainties.append("Investigation was incomplete because the runtime limit was reached.")
        report = self.report_generator.generate(context, graph, hypotheses, evaluation, activities, state)
        self.reports[investigation_id] = report
        return report

    def investigate_alert(self, alert_id: str) -> AnalystReport:
        alert: ThreatLensAlertResponse = self.threatlens_client.fetch_alert(alert_id)
        return self.investigate(self.threatlens_client.to_investigation_request(alert))

    def get(self, investigation_id: str) -> AnalystReport | None:
        return self.reports.get(investigation_id)
