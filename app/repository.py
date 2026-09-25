from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from app.engine.assessment import reconcile_assessment
from app.engine.report_validation import validate_report_integrity
from app.llm.schemas import AnalystAssessment, validate_assessment
from app.models import AnalystReport, Evaluation

logger = logging.getLogger(__name__)


class InvestigationRepositoryError(RuntimeError):
    """Raised when durable investigation history cannot be safely used."""


@dataclass(frozen=True)
class PersistedInvestigation:
    investigation_id: str
    alert_id: str | None
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    stop_reason: str | None
    error: str | None
    timeout: bool
    created_at: datetime
    updated_at: datetime
    report: AnalystReport | None = None


class InvestigationRepository(Protocol):
    def create(self, investigation: PersistedInvestigation) -> None: ...

    def save(self, investigation: PersistedInvestigation) -> None: ...

    def get(self, investigation_id: str) -> PersistedInvestigation | None: ...

    def list(self, limit: int = 20, offset: int = 0) -> list[PersistedInvestigation]: ...


class SQLiteInvestigationRepository:
    """Small SQLite implementation for a single ORION instance.

    Connections are intentionally short-lived so independent request threads can
    read safely. WAL mode keeps readers from being blocked by the service's
    brief final-state write.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS investigations (
        investigation_id TEXT PRIMARY KEY,
        alert_id TEXT NULL,
        status TEXT NOT NULL,
        started_at TEXT NULL,
        completed_at TEXT NULL,
        stop_reason TEXT NULL,
        error TEXT NULL,
        timeout INTEGER NOT NULL DEFAULT 0,
        report_json TEXT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_investigations_alert_id
        ON investigations(alert_id);
    CREATE INDEX IF NOT EXISTS idx_investigations_created_at
        ON investigations(created_at DESC);
    """

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.database_path, timeout=5.0)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 5000")
            return connection
        except sqlite3.Error as exc:
            raise InvestigationRepositoryError("Unable to open investigation database") from exc

    def _initialize(self) -> None:
        try:
            if self.database_path != ":memory:":
                Path(self.database_path).expanduser().parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.executescript(self._SCHEMA)
            logger.info("Investigation repository initialized database_path=%s", self.database_path)
        except (OSError, sqlite3.Error, InvestigationRepositoryError) as exc:
            logger.exception("Investigation database initialization failed")
            if isinstance(exc, InvestigationRepositoryError):
                raise
            raise InvestigationRepositoryError("Unable to initialize investigation database") from exc

    def create(self, investigation: PersistedInvestigation) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO investigations (
                        investigation_id, alert_id, status, started_at, completed_at,
                        stop_reason, error, timeout, report_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    self._values(investigation),
                )
            logger.info("Investigation persisted investigation_id=%s status=%s", investigation.investigation_id, investigation.status)
        except sqlite3.Error as exc:
            logger.exception("Investigation create failed investigation_id=%s", investigation.investigation_id)
            raise InvestigationRepositoryError("Unable to create investigation history") from exc

    def save(self, investigation: PersistedInvestigation) -> None:
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO investigations (
                        investigation_id, alert_id, status, started_at, completed_at,
                        stop_reason, error, timeout, report_json, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(investigation_id) DO UPDATE SET
                        alert_id = excluded.alert_id,
                        status = excluded.status,
                        started_at = excluded.started_at,
                        completed_at = excluded.completed_at,
                        stop_reason = excluded.stop_reason,
                        error = excluded.error,
                        timeout = excluded.timeout,
                        report_json = excluded.report_json,
                        updated_at = excluded.updated_at""",
                    self._values(investigation),
                )
            logger.info("Investigation persisted investigation_id=%s status=%s", investigation.investigation_id, investigation.status)
        except sqlite3.Error as exc:
            logger.exception("Investigation save failed investigation_id=%s", investigation.investigation_id)
            raise InvestigationRepositoryError("Unable to save investigation history") from exc

    def get(self, investigation_id: str) -> PersistedInvestigation | None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM investigations WHERE investigation_id = ?", (investigation_id,)
                ).fetchone()
        except sqlite3.Error as exc:
            logger.exception("Investigation load failed investigation_id=%s", investigation_id)
            raise InvestigationRepositoryError("Unable to load investigation history") from exc
        if row is None:
            return None
        result = self._row_to_investigation(row)
        logger.info("Investigation loaded investigation_id=%s", investigation_id)
        return result

    def list(self, limit: int = 20, offset: int = 0) -> list[PersistedInvestigation]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        if offset < 0:
            raise ValueError("offset must be greater than or equal to zero")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """SELECT investigation_id, alert_id, status, started_at, completed_at,
                              stop_reason, error, timeout, created_at, updated_at
                       FROM investigations
                       ORDER BY created_at DESC, investigation_id DESC LIMIT ? OFFSET ?""",
                    (limit, offset),
                ).fetchall()
        except sqlite3.Error as exc:
            logger.exception("Investigation list failed")
            raise InvestigationRepositoryError("Unable to list investigation history") from exc
        return [self._row_to_investigation(row) for row in rows]

    def _values(self, investigation: PersistedInvestigation) -> tuple[object, ...]:
        report_json = None
        if investigation.report is not None:
            self._validate_report(investigation.report)
            report_json = json.dumps(
                investigation.report.model_dump(mode="json"), separators=(",", ":"), ensure_ascii=False
            )
        return (
            investigation.investigation_id,
            investigation.alert_id,
            investigation.status,
            _serialize_datetime(investigation.started_at),
            _serialize_datetime(investigation.completed_at),
            investigation.stop_reason,
            investigation.error,
            int(investigation.timeout),
            report_json,
            _serialize_datetime(investigation.created_at),
            _serialize_datetime(investigation.updated_at),
        )

    def _row_to_investigation(self, row: sqlite3.Row) -> PersistedInvestigation:
        report = None
        if "report_json" in row.keys() and row["report_json"] is not None:
            try:
                report = self._validate_report(AnalystReport.model_validate(json.loads(row["report_json"])))
            except (json.JSONDecodeError, TypeError, ValidationError, ValueError) as exc:
                logger.error("Persisted report validation failed investigation_id=%s", row["investigation_id"])
                raise InvestigationRepositoryError("Persisted investigation report is invalid") from exc
        try:
            return PersistedInvestigation(
                investigation_id=row["investigation_id"],
                alert_id=row["alert_id"],
                status=row["status"],
                started_at=_parse_datetime(row["started_at"]),
                completed_at=_parse_datetime(row["completed_at"]),
                stop_reason=row["stop_reason"],
                error=row["error"],
                timeout=bool(row["timeout"]),
                created_at=_parse_datetime(row["created_at"], required=True),
                updated_at=_parse_datetime(row["updated_at"], required=True),
                report=report,
            )
        except (TypeError, ValueError) as exc:
            raise InvestigationRepositoryError("Persisted investigation metadata is invalid") from exc

    @staticmethod
    def _validate_report(report: AnalystReport) -> AnalystReport:
        """Reapply the report's domain and assessment safeguards on every load/save."""
        validate_report_integrity(report)
        assessment = None
        if report.llm_assessment is not None:
            assessment = validate_assessment(
                AnalystAssessment.model_validate(report.llm_assessment),
                {item.id for item in report.evidence},
                {item.id for item in report.hypotheses},
                report.missing_evidence,
            )
        # The investigation service may deliberately mark consistency as invalid
        # when its existing reconciliation guard fails. That case is safe only
        # when the deterministic assessment is retained unchanged.
        if report.assessment_consistency.status.value == "invalid":
            if report.final_assessment != report.deterministic_assessment:
                raise ValueError("Persisted invalid assessment did not preserve the deterministic assessment")
        else:
            expected_deterministic, expected_final, expected_consistency = reconcile_assessment(
                assessment,
                Evaluation(
                    classification=report.classification,
                    confidence=report.confidence,
                    missing_evidence=report.missing_evidence,
                    needs_investigation=report.human_review_required,
                ),
                report.severity,
                report.hypotheses,
            )
            if (
                report.deterministic_assessment != expected_deterministic
                or report.final_assessment != expected_final
                or report.assessment_consistency != expected_consistency
            ):
                raise ValueError("Persisted report failed assessment consistency validation")
        return report


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _serialize_datetime(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_datetime(value: str | None, *, required: bool = False) -> datetime | None:
    if value is None:
        if required:
            raise ValueError("required timestamp is missing")
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)
