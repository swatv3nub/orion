import logging

from fastapi import FastAPI, HTTPException, Path, Query

from app.integrations.threatlens import ThreatLensError
from app.models import InvestigationListResponse, InvestigationMetadata, InvestigationRequest, InvestigationResponse
from app.repository import InvestigationRepositoryError, PersistedInvestigation
from app.service import InvestigationService

app = FastAPI(title="ORION", version="1.0.0")
service = InvestigationService()
logger = logging.getLogger(__name__)


@app.get("/v1/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/investigations", response_model=InvestigationResponse, status_code=201)
def create_investigation(request: InvestigationRequest) -> InvestigationResponse:
    report = service.investigate(request)
    return InvestigationResponse(
        investigation_id=report.investigation_id,
        alert_id=report.alert_id,
        status=report.state.status if report.state else "completed",
        classification=report.classification,
    )


@app.post("/v1/investigations/from-alert/{alert_id}", response_model=InvestigationResponse, status_code=201)
def create_from_alert(alert_id: str = Path(pattern=r"^[A-Za-z0-9_.:-]+$", min_length=1, max_length=200)) -> InvestigationResponse:
    try:
        report = service.investigate_alert(alert_id)
    except ThreatLensError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.public_message) from None
    return InvestigationResponse(
        investigation_id=report.investigation_id,
        alert_id=report.alert_id,
        status=report.state.status if report.state else "completed",
        classification=report.classification,
    )


@app.get("/v1/investigations", response_model=InvestigationListResponse)
def list_investigations(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> InvestigationListResponse:
    try:
        investigations = service.list_investigations(limit=limit, offset=offset)
    except InvestigationRepositoryError as exc:
        logger.exception("Unable to list persisted investigations")
        raise HTTPException(status_code=500, detail="Investigation history is unavailable") from exc
    return InvestigationListResponse(
        investigations=[_metadata(item) for item in investigations], limit=limit, offset=offset
    )


@app.get("/v1/investigations/{investigation_id}")
def get_investigation(investigation_id: str):
    try:
        investigation = service.get_investigation(investigation_id)
    except InvestigationRepositoryError as exc:
        logger.exception("Unable to load persisted investigation investigation_id=%s", investigation_id)
        raise HTTPException(status_code=500, detail="Persisted investigation data is invalid") from exc
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    # Preserve the established detail response while sourcing it exclusively
    # from durable history rather than process-local state.
    return {**_metadata(investigation).model_dump(mode="json"), "report": investigation.report}


@app.get("/v1/investigations/{investigation_id}/report")
def get_report(investigation_id: str):
    try:
        investigation = service.get_investigation(investigation_id)
    except InvestigationRepositoryError as exc:
        logger.exception("Unable to load persisted report investigation_id=%s", investigation_id)
        raise HTTPException(status_code=500, detail="Persisted investigation data is invalid") from exc
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if investigation.report is None:
        raise HTTPException(status_code=404, detail="Investigation report not found")
    return investigation.report


def _metadata(investigation: PersistedInvestigation) -> InvestigationMetadata:
    return InvestigationMetadata(
        investigation_id=investigation.investigation_id,
        alert_id=investigation.alert_id,
        status=investigation.status,
        started_at=investigation.started_at,
        completed_at=investigation.completed_at,
        stop_reason=investigation.stop_reason,
        error=investigation.error,
        timeout=investigation.timeout,
        created_at=investigation.created_at,
        updated_at=investigation.updated_at,
    )
