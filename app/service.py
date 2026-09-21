from __future__ import annotations

from uuid import uuid4

from app.engine.context import ContextBuilder
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.report import ReportGenerator
from app.models import AnalystReport, InvestigationRequest


class InvestigationService:
    def __init__(self) -> None:
        self.context_builder = ContextBuilder()
        self.hypothesis_engine = HypothesisEngine()
        self.evaluator = EvidenceEvaluator()
        self.report_generator = ReportGenerator()
        self.reports: dict[str, AnalystReport] = {}

    def investigate(self, request: InvestigationRequest) -> AnalystReport:
        investigation_id = f"INV-{uuid4().hex[:12]}"
        context = self.context_builder.build(request, investigation_id)
        graph = build_graph(context)
        hypotheses = self.hypothesis_engine.generate(context, graph)
        for hypothesis in hypotheses:
            graph.add_node(hypothesis.id, "hypothesis", hypothesis.model_dump(mode="json"))
            for evidence_id in hypothesis.supporting_evidence:
                if graph.get_node(evidence_id):
                    graph.add_edge(evidence_id, hypothesis.id, "supports")
            for evidence_id in hypothesis.contradicting_evidence:
                if graph.get_node(evidence_id):
                    graph.add_edge(evidence_id, hypothesis.id, "contradicts")
        evaluation = self.evaluator.evaluate(context, hypotheses)
        report = self.report_generator.generate(context, graph, hypotheses, evaluation)
        self.reports[investigation_id] = report
        return report

    def get(self, investigation_id: str) -> AnalystReport | None:
        return self.reports.get(investigation_id)
