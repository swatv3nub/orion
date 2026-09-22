from __future__ import annotations

import logging
from uuid import uuid4

from app.config import Settings
from app.integrations.threatlens import ThreatLensClient, ThreatLensAlertResponse
from app.engine.context import ContextBuilder
from app.engine.correlator import EvidenceCorrelator
from app.engine.evaluator import EvidenceEvaluator
from app.engine.graph import build_graph
from app.engine.hypotheses import HypothesisEngine
from app.engine.executor import InvestigationExecutor
from app.engine.missing import MissingEvidenceAnalyzer
from app.engine.planner import InvestigationPlanner
from app.engine.report import ReportGenerator
from app.llm import LLMError, LLMReasoner, create_reasoner
from app.llm.schemas import validate_assessment
from app.policy import PolicyEngine
from app.models import AnalystReport, InvestigationRequest
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

class InvestigationService:
    def __init__(self, settings: Settings | None = None, registry: ToolRegistry | None = None, threatlens_client: ThreatLensClient | None = None, llm_reasoner: LLMReasoner | None = None) -> None:
        settings = settings or Settings.from_env()
        registry = registry or ToolRegistry(settings)
        self.threatlens_client = threatlens_client or ThreatLensClient(settings)
        self.context_builder = ContextBuilder()
        self.correlator = EvidenceCorrelator()
        self.hypothesis_engine = HypothesisEngine()
        self.evaluator = EvidenceEvaluator()
        self.missing_analyzer = MissingEvidenceAnalyzer()
        self.planner = InvestigationPlanner()
        self.executor = InvestigationExecutor(registry, PolicyEngine(settings, registry), settings)
        self.report_generator = ReportGenerator()
        self.llm_reasoner = llm_reasoner or create_reasoner(settings)
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
        correlation = self.correlator.correlate(context, graph)
        state.evidence_count = len(context.evidence)
        hypotheses = self.hypothesis_engine.generate(context, graph, correlation)
        for hypothesis in hypotheses:
            graph.add_node(hypothesis.id, "hypothesis", hypothesis.model_dump(mode="json"))
            for evidence_id in hypothesis.supporting_evidence + hypothesis.contextual_evidence:
                graph.add_edge(hypothesis.id, evidence_id, "supported_by" if evidence_id in hypothesis.supporting_evidence else "contextualizes")
        evaluation = self.evaluator.evaluate(context, hypotheses)
        missing_items = self.missing_analyzer.analyze(context, graph, hypotheses)
        insufficient = list(dict.fromkeys(item for hypothesis in hypotheses for item in hypothesis.missing_evidence))
        evaluation.missing_evidence = list(dict.fromkeys([item.description for item in missing_items] + insufficient))
        if insufficient:
            evaluation.uncertainties.append("Retrieved evidence is insufficient to establish: " + ", ".join(insufficient) + ".")
        if state.timeout:
            evaluation.uncertainties.append("Investigation was incomplete because the runtime limit was reached.")
        assessment = None
        llm_status = "not_configured" if self.llm_reasoner is None else "failed"
        llm_failure_reason = None
        llm_provider = None
        llm_model = None
        llm_fallback_used = False
        llm_primary_failure_reason = None
        if self.llm_reasoner:
            try:
                assessment = self.llm_reasoner.analyze(context.primary_alert, context.evidence, hypotheses, evaluation.missing_evidence, activities)
                validate_assessment(assessment, {item.id for item in context.evidence}, {item.id for item in hypotheses}, evaluation.missing_evidence)
                llm_status = "success"
                llm_provider = self.llm_reasoner.provider
                llm_model = self.llm_reasoner.model
                llm_fallback_used = self.llm_reasoner.fallback_used
                llm_primary_failure_reason = self.llm_reasoner.primary_failure_reason
                logger.info("LLM assessment succeeded provider=%s model=%s", llm_provider, llm_model)
            except LLMError as exc:
                assessment = None
                if not state.timeout:
                    state.status, state.stop_reason, state.error = "partial", exc.code, exc.code
                evaluation.uncertainties.append("LLM assessment was unavailable or failed validation; deterministic analysis was preserved.")
                llm_failure_reason = exc.code
                llm_provider = self.llm_reasoner.provider
                llm_model = self.llm_reasoner.model
                llm_fallback_used = self.llm_reasoner.fallback_used
                llm_primary_failure_reason = self.llm_reasoner.primary_failure_reason
                logger.warning("LLM assessment failed provider=%s model=%s reason=%s", llm_provider, llm_model, exc.code)
            except ValueError:
                assessment = None
                if not state.timeout:
                    state.status, state.stop_reason, state.error = "partial", "llm_validation_failed", "llm_validation_failed"
                evaluation.uncertainties.append("LLM assessment was unavailable or failed validation; deterministic analysis was preserved.")
                llm_failure_reason = "llm_validation_failed"
                logger.warning("LLM assessment failed reason=%s", llm_failure_reason)
            except Exception:
                assessment = None
                if not state.timeout:
                    state.status, state.stop_reason, state.error = "partial", "llm_error", "llm_error"
                evaluation.uncertainties.append("LLM assessment was unavailable or failed validation; deterministic analysis was preserved.")
                llm_failure_reason = "llm_error"
                logger.warning("LLM assessment failed reason=%s", llm_failure_reason)
        report = self.report_generator.generate(
            context, graph, hypotheses, evaluation, activities, state, correlation,
            assessment.model_dump(mode="json") if assessment else None, llm_status, llm_model, llm_failure_reason,
            llm_provider, llm_fallback_used, llm_primary_failure_reason,
        )
        self.reports[investigation_id] = report
        return report

    def investigate_alert(self, alert_id: str) -> AnalystReport:
        alert: ThreatLensAlertResponse = self.threatlens_client.fetch_alert(alert_id)
        return self.investigate(self.threatlens_client.to_investigation_request(alert))

    def get(self, investigation_id: str) -> AnalystReport | None:
        return self.reports.get(investigation_id)
