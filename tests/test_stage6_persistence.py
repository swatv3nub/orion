from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timezone

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.engine.executor import InvestigationExecutor
from app.main import app
from app.policy import PolicyEngine
from app.repository import (
    InvestigationRepositoryError,
    PersistedInvestigation,
    SQLiteInvestigationRepository,
    utc_now,
)
from app.service import InvestigationService
from app.tools.registry import ToolRegistry
from tests.test_stage1 import request
from tests.test_stage2 import FakeThreatLens
from tests.test_stage5 import AssessmentReasoner, UnavailableReasoner


def settings(tmp_path) -> Settings:
    return Settings(database_path=str(tmp_path / "orion.db"))


def service(tmp_path, reasoner=None) -> InvestigationService:
    return InvestigationService(
        settings=settings(tmp_path),
        registry=ToolRegistry(tools=[FakeThreatLens()]),
        llm_reasoner=reasoner,
    )


def record(identifier: str, *, status: str = "pending") -> PersistedInvestigation:
    now = utc_now()
    return PersistedInvestigation(
        investigation_id=identifier,
        alert_id="alert-1",
        status=status,
        started_at=now,
        completed_at=None,
        stop_reason=None,
        error=None,
        timeout=False,
        created_at=now,
        updated_at=now,
    )


def test_database_path_is_read_from_environment(monkeypatch, tmp_path):
    path = str(tmp_path / "configured.db")
    monkeypatch.setenv("ORION_DATABASE_PATH", path)

    assert Settings.from_env().database_path == path


def test_repository_initializes_empty_database_and_uses_utc_timestamps(tmp_path):
    database = tmp_path / "nested" / "orion.db"
    repository = SQLiteInvestigationRepository(str(database))

    assert database.exists()
    assert repository.list() == []
    repository.create(record("INV-utc"))
    loaded = repository.get("INV-utc")
    assert loaded is not None
    assert loaded.created_at.tzinfo == timezone.utc


def test_repository_create_save_get_list_and_pagination(tmp_path):
    repository = SQLiteInvestigationRepository(str(tmp_path / "orion.db"))
    for number in range(3):
        item = record(f"INV-{number}")
        repository.create(item)
        repository.save(PersistedInvestigation(**{**item.__dict__, "status": "completed", "updated_at": utc_now()}))

    loaded = repository.get("INV-1")
    assert loaded is not None
    assert loaded.status == "completed"
    assert repository.get("INV-missing") is None
    assert [item.investigation_id for item in repository.list(limit=2, offset=0)] == ["INV-2", "INV-1"]
    assert [item.investigation_id for item in repository.list(limit=2, offset=2)] == ["INV-0"]
    assert len(repository.list(limit=100)) == 3
    with pytest.raises(ValueError):
        repository.list(limit=101)
    with pytest.raises(ValueError):
        repository.list(offset=-1)


def test_repository_persists_and_reconstructs_validated_report(tmp_path):
    first_service = service(tmp_path, AssessmentReasoner())
    report = first_service.investigate(request())

    # A new service object has no process-local report state to rely on.
    second_service = service(tmp_path, AssessmentReasoner())
    loaded = second_service.get(report.investigation_id)
    assert loaded == report
    assert loaded.llm_assessment is not None
    assert loaded.deterministic_assessment != loaded.final_assessment
    assert loaded.assessment_consistency.status == "reconciled"
    assert loaded.human_review_required
    assert loaded.automated_action == "none"


def test_partial_and_timeout_reports_are_persisted(tmp_path):
    partial_service = service(tmp_path, UnavailableReasoner())
    partial = partial_service.investigate(request())
    assert partial_service.get_investigation(partial.investigation_id).status == "partial"

    timeout_settings = Settings(database_path=str(tmp_path / "timeout.db"), max_runtime_seconds=0.1)
    registry = ToolRegistry(tools=[FakeThreatLens()])
    timeout_service = InvestigationService(settings=timeout_settings, registry=registry, llm_reasoner=UnavailableReasoner())
    clock_values = iter([0.0, 0.0, 0.0, 1.0])
    clock = lambda: next(clock_values, 1.0)
    timeout_service.executor = InvestigationExecutor(
        registry, PolicyEngine(timeout_settings, registry, clock), timeout_settings, clock
    )
    timeout = timeout_service.investigate(request())
    persisted_timeout = timeout_service.get_investigation(timeout.investigation_id)
    assert persisted_timeout.status == "timeout"
    assert persisted_timeout.timeout
    assert persisted_timeout.report is not None


def test_service_persists_failure_before_report_generation(tmp_path):
    failing_service = service(tmp_path, AssessmentReasoner())

    class BrokenContextBuilder:
        def build(self, *args):
            raise RuntimeError("unexpected internal failure")

    failing_service.context_builder = BrokenContextBuilder()
    with pytest.raises(RuntimeError):
        failing_service.investigate(request())

    failed = failing_service.list_investigations()[0]
    assert failed.status == "partial"
    assert failed.error == "investigation_error"
    assert failed.report is None


def test_null_report_for_failed_investigation_and_malformed_reports_are_rejected(tmp_path):
    database = str(tmp_path / "orion.db")
    repository = SQLiteInvestigationRepository(database)
    repository.create(record("INV-failed", status="partial"))
    assert repository.get("INV-failed").report is None

    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE investigations SET report_json = ? WHERE investigation_id = ?", ("{bad json", "INV-failed"))
    with pytest.raises(InvestigationRepositoryError, match="invalid"):
        repository.get("INV-failed")


def test_concurrent_reads_are_safe(tmp_path):
    repository = SQLiteInvestigationRepository(str(tmp_path / "orion.db"))
    repository.create(record("INV-concurrent"))
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: repository.get("INV-concurrent"), range(24)))
    assert all(item is not None and item.investigation_id == "INV-concurrent" for item in results)


def test_history_api_uses_persisted_repository(monkeypatch, tmp_path):
    import app.main as main_module

    previous = main_module.service
    history_service = service(tmp_path, AssessmentReasoner())
    main_module.service = history_service
    try:
        client = TestClient(app)
        created = client.post("/v1/investigations", json=request().model_dump(mode="json"))
        assert created.status_code == 201
        identifier = created.json()["investigation_id"]

        assert client.get(f"/v1/investigations/{identifier}").status_code == 200
        report_response = client.get(f"/v1/investigations/{identifier}/report")
        assert report_response.status_code == 200
        assert report_response.json()["automated_action"] == "none"
        assert "database_path" not in report_response.text
        assert client.get("/v1/investigations?limit=1&offset=0").json()["investigations"][0]["investigation_id"] == identifier
        assert client.get("/v1/investigations?limit=101").status_code == 422
        assert client.get("/v1/investigations/missing").status_code == 404
    finally:
        main_module.service = previous
