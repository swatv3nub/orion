from fastapi import FastAPI, HTTPException, Path

from app.integrations.threatlens import ThreatLensError
from app.models import InvestigationRequest, InvestigationResponse
from app.service import InvestigationService

app = FastAPI(title="ORION", version="1.0.0")
service = InvestigationService()


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


@app.get("/v1/investigations/{investigation_id}")
def get_investigation(investigation_id: str):
    report = service.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {"investigation_id": investigation_id, "status": report.state.status if report.state else "completed", "report": report}


@app.get("/v1/investigations/{investigation_id}/report")
def get_report(investigation_id: str):
    report = service.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return report
