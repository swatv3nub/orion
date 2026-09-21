from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.integrations import threatlens as threatlens_module
from app.integrations.threatlens import (
    ThreatLensAlertResponse,
    ThreatLensAuthenticationError,
    ThreatLensClient,
    ThreatLensMalformedResponseError,
    ThreatLensTimeoutError,
)
from app.main import app
from app.service import InvestigationService
from app.tools.registry import ToolRegistry
from tests.test_stage2 import FakeIntentionalHistory, FakeReconix


FIXTURE = json.loads(Path("examples/threatlens_alert.json").read_text())


class FakeResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self.fp = None
        self.body = body

    def read(self, limit: int = -1) -> bytes:
        return self.body


class FakeConnection:
    response = FakeResponse(200, json.dumps(FIXTURE).encode())
    error: Exception | None = None
    requested_path = ""

    def __init__(self, *args, **kwargs):
        pass

    def request(self, method: str, path: str, headers: dict[str, str]):
        self.requested_path = path
        if self.error:
            raise self.error

    def getresponse(self):
        return self.response

    def close(self):
        pass


def client(monkeypatch, response: FakeResponse | None = None) -> ThreatLensClient:
    FakeConnection.response = response or FakeResponse(200, json.dumps(FIXTURE).encode())
    FakeConnection.error = None
    monkeypatch.setattr(threatlens_module.http.client, "HTTPConnection", FakeConnection)
    return ThreatLensClient(Settings(threatlens_base_url="http://threatlens.test", threatlens_api_key="secret"))


def test_threatlens_alert_fetch_and_metadata_conversion(monkeypatch):
    fetched = client(monkeypatch).fetch_alert("finding_demo_001")
    request = ThreatLensClient(Settings()).to_investigation_request(fetched)
    assert fetched.identifier == "finding_demo_001"
    assert request.context.model_extra["scan_id"] == "scan_demo_001"
    assert request.context.model_extra["finding_id"] == "finding_demo_001"
    assert request.finding.evidence["status"] == 401
    assert request.finding.model_extra["port"] == 443


def test_threatlens_authentication_failure_is_safe(monkeypatch):
    with pytest.raises(ThreatLensAuthenticationError) as error:
        client(monkeypatch, FakeResponse(401, b'{"secret":"not returned"}')).fetch_alert("finding_demo_001")
    assert "secret" not in str(error.value)


def test_threatlens_malformed_response_is_rejected(monkeypatch):
    with pytest.raises(ThreatLensMalformedResponseError):
        client(monkeypatch, FakeResponse(200, b'{"id":"missing-severity"}')).fetch_alert("finding_demo_001")


def test_threatlens_timeout_is_typed(monkeypatch):
    FakeConnection.error = TimeoutError()
    monkeypatch.setattr(threatlens_module.http.client, "HTTPConnection", FakeConnection)
    with pytest.raises(ThreatLensTimeoutError):
        ThreatLensClient(Settings(threatlens_base_url="http://threatlens.test")).fetch_alert("finding_demo_001")


def test_from_alert_endpoint_runs_existing_service(monkeypatch):
    fetched = ThreatLensAlertResponse.model_validate(FIXTURE)

    class FakeClient:
        def fetch_alert(self, alert_id: str):
            assert alert_id == "finding_demo_001"
            return fetched

        def to_investigation_request(self, alert):
            return ThreatLensClient(Settings()).to_investigation_request(alert)

    import app.main as main_module
    previous = main_module.service
    main_module.service = InvestigationService(settings=Settings(), registry=ToolRegistry(tools=[FakeIntentionalHistory(), FakeReconix()]), threatlens_client=FakeClient())
    try:
        response = TestClient(app).post("/v1/investigations/from-alert/finding_demo_001")
        assert response.status_code == 201
        body = response.json()
        assert body["alert_id"] == "finding_demo_001"
        assert body["investigation_id"].startswith("INV-")
    finally:
        main_module.service = previous


def test_from_alert_rejects_arbitrary_target(monkeypatch):
    response = TestClient(app).post("/v1/investigations/from-alert/https%3A%2F%2Farbitrary.example")
    assert response.status_code in {404, 422}


def test_end_to_end_fixture_preserves_correlation_and_provenance():
    fetched = ThreatLensAlertResponse.model_validate(FIXTURE)

    class FakeClient:
        def fetch_alert(self, alert_id: str):
            return fetched

        def to_investigation_request(self, alert):
            return ThreatLensClient(Settings()).to_investigation_request(alert)

    service = InvestigationService(
        settings=Settings(),
        registry=ToolRegistry(tools=[FakeIntentionalHistory(), FakeReconix()]),
        threatlens_client=FakeClient(),
    )
    report = service.investigate_alert("finding_demo_001")
    assert report.alert_id == "finding_demo_001"
    assert report.investigation_id
    assert report.tool_activity
    assert report.stop_reason
    assert report.automated_action == "none"
    assert any(e.raw_reference == "scan_demo_001" for e in report.evidence)
    assert all(e.source in {"reconix_cloud", "threatlens", "mitre"} for e in report.evidence)
