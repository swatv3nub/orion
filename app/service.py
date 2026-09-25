from __future__ import annotations

import logging
from datetime import datetime
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
from app.engine.assessment import reconcile_assessment
from app.llm import LLMError, LLMReasoner, create_reasoner
from app.llm.schemas import validate_assessment
from app.policy import PolicyEngine
from app.models import AssessmentConsistency, AssessmentConsistencyStatus, AnalystReport, InvestigationRequest
from app.repository import (
    InvestigationRepository,
    PersistedInvestigation,
    SQLiteInvestigationRepository,
    utc_now,
)
from app.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)

class InvestigationService:
    def __init__(
        self,
        settings: Settings | None = None,
        registry: ToolRegistry | None = None,
        threatlens_client: ThreatLensClient | None = None,
        llm_reasoner: LLMReasoner | None = None,
        repository: InvestigationRepository | None = None,
    ) -> None:
        settings = settings or Settings.from_env()
        self.settings = settings
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
        self.repository = repository or SQLiteInvestigationRepository(settings.database_path)

    def investigate(self, request: InvestigationRequest) -> AnalystReport:
        investigation_id = f"INV-{uuid4().hex[:12]}"
        created_at = utc_now()
        self.repository.create(PersistedInvestigation(
            investigation_id=investigation_id,
            alert_id=request.alert_id,
            status="pending",
            started_at=created_at,
            completed_at=None,
            stop_reason=None,
            error=None,
            timeout=False,
            created_at=created_at,
            updated_at=created_at,
        ))
        state = None
        try:
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
                except ValueError as exc:
                    assessment = None
                    if not state.timeout:
                        state.status, state.stop_reason, state.error = "partial", "llm_validation_failed", "llm_validation_failed"
                    evaluation.uncertainties.append("LLM assessment was unavailable or failed validation; deterministic analysis was preserved.")
                    llm_failure_reason = "llm_validation_failed"
                    llm_provider = self.llm_reasoner.provider
                    llm_model = self.llm_reasoner.model
                    llm_fallback_used = self.llm_reasoner.fallback_used
                    llm_primary_failure_reason = self.llm_reasoner.primary_failure_reason
                    logger.warning("LLM assessment failed reason=%s exception=%s", llm_failure_reason, type(exc).__name__)
                except Exception:
                    assessment = None
                    if not state.timeout:
                        state.status, state.stop_reason, state.error = "partial", "llm_error", "llm_error"
                    evaluation.uncertainties.append("LLM assessment was unavailable or failed validation; deterministic analysis was preserved.")
                    llm_failure_reason = "llm_error"
                    llm_provider = self.llm_reasoner.provider
                    llm_model = self.llm_reasoner.model
                    llm_fallback_used = self.llm_reasoner.fallback_used
                    llm_primary_failure_reason = self.llm_reasoner.primary_failure_reason
                    logger.warning("LLM assessment failed reason=%s", llm_failure_reason)
            try:
                deterministic_assessment, final_assessment, consistency = reconcile_assessment(
                    assessment, evaluation, context.primary_alert.finding.severity, hypotheses
                )
            except Exception:
                deterministic_assessment, final_assessment, _ = reconcile_assessment(
                    None, evaluation, context.primary_alert.finding.severity, hypotheses
                )
                consistency = AssessmentConsistency(
                    status=AssessmentConsistencyStatus.invalid,
                    reason="Assessment consistency validation failed; deterministic assessment preserved.",
                )
            report = self.report_generator.generate(
                context, graph, hypotheses, evaluation, activities, state, correlation,
                assessment.model_dump(mode="json") if assessment else None, llm_status, llm_model, llm_failure_reason,
                llm_provider, llm_fallback_used, llm_primary_failure_reason,
                deterministic_assessment, final_assessment, consistency,
            )
            self.repository.save(self._record_for_report(report, created_at))
            return report
        except Exception:
            # Keep error persistence and diagnostics controlled: exceptions from
            # integrations can contain untrusted remote response text.
            logger.error("Investigation failed investigation_id=%s", investigation_id)
            self.repository.save(PersistedInvestigation(
                investigation_id=investigation_id,
                alert_id=request.alert_id,
                status="timeout" if state is not None and state.timeout else "partial",
                started_at=state.started_at if state is not None else created_at,
                completed_at=state.completed_at if state is not None and state.completed_at is not None else utc_now(),
                stop_reason=state.stop_reason if state is not None and state.stop_reason else "investigation_error",
                error=state.error if state is not None and state.error else "investigation_error",
                timeout=state.timeout if state is not None else False,
                created_at=created_at,
                updated_at=utc_now(),
            ))
            raise

    def investigate_alert(self, alert_id: str) -> AnalystReport:
        alert: ThreatLensAlertResponse = self.threatlens_client.fetch_alert(alert_id)
        return self.investigate(self.threatlens_client.to_investigation_request(alert))

    def get(self, investigation_id: str) -> AnalystReport | None:
        investigation = self.repository.get(investigation_id)
        return investigation.report if investigation is not None else None

    def get_investigation(self, investigation_id: str) -> PersistedInvestigation | None:
        return self.repository.get(investigation_id)

    def list_investigations(self, limit: int = 20, offset: int = 0) -> list[PersistedInvestigation]:
        return self.repository.list(limit=limit, offset=offset)

    @staticmethod
    def _record_for_report(report: AnalystReport, created_at: datetime) -> PersistedInvestigation:
        state = report.state
        now = utc_now()
        return PersistedInvestigation(
            investigation_id=report.investigation_id,
            alert_id=report.alert_id,
            status=state.status if state else "completed",
            started_at=state.started_at if state else None,
            completed_at=state.completed_at if state else now,
            stop_reason=state.stop_reason if state else report.stop_reason,
            error=state.error if state else None,
            timeout=state.timeout if state else False,
            created_at=created_at,
            updated_at=now,
            report=report,
        )
