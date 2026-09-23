from __future__ import annotations

import http.client
import json
import socket
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import Settings
from app.models import AlertContext, Asset, Finding, InvestigationRequest, Severity

MAX_RESPONSE_BYTES = 1_000_000


class ThreatLensError(Exception):
    status_code = 502
    public_message = "ThreatLens request failed"


class ThreatLensAuthenticationError(ThreatLensError):
    status_code = 502
    public_message = "ThreatLens authentication failed"


class ThreatLensNotFoundError(ThreatLensError):
    status_code = 404
    public_message = "ThreatLens alert not found"


class ThreatLensTimeoutError(ThreatLensError):
    status_code = 504
    public_message = "ThreatLens request timed out"


class ThreatLensMalformedResponseError(ThreatLensError):
    status_code = 502
    public_message = "ThreatLens returned a malformed alert"


class ThreatLensAlertResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str | None = Field(default=None, min_length=1)
    alert_id: str | None = Field(default=None, min_length=1)
    source: str = Field(min_length=1)
    timestamp: datetime | None = None
    severity: Severity
    category: str | None = None
    raw_event: dict[str, Any]
    metadata: dict[str, Any]
    asset: dict[str, Any] | None = None

    @property
    def identifier(self) -> str:
        identifier = self.id or self.alert_id

        if not identifier:
            raise ThreatLensMalformedResponseError(
                "alert identifier missing"
            )

        return identifier


class ThreatLensClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def fetch_alert(self, alert_id: str) -> ThreatLensAlertResponse:
        base = urlsplit(self.settings.threatlens_base_url)

        # ------------------------------------------------------------
        # Configuration validation
        # ------------------------------------------------------------

        if base.scheme not in {"http", "https"} or not base.netloc:
            raise ThreatLensError(
                "ThreatLens is not configured with a valid HTTP(S) base URL"
            )

        if not alert_id or any(
            char not in (
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789_.:-"
            )
            for char in alert_id
        ):
            raise ThreatLensError("invalid alert identifier")

        connection: (
            http.client.HTTPConnection
            | http.client.HTTPSConnection
        )

        connection_type = (
            http.client.HTTPSConnection
            if base.scheme == "https"
            else http.client.HTTPConnection
        )

        connection = connection_type(
            base.netloc,
            timeout=self.settings.threatlens_connect_timeout_seconds,
        )

        path = (
            f"{base.path.rstrip('/')}"
            f"/v1/alerts/{quote(alert_id, safe='._:-')}"
        )

        if base.query:
            path = f"{path}?{base.query}"

        headers = {
            "Accept": "application/json",
        }

        if self.settings.threatlens_api_key:
            headers["Authorization"] = (
                f"Bearer {self.settings.threatlens_api_key}"
            )

        try:
            # --------------------------------------------------------
            # Request
            # --------------------------------------------------------

            try:
                connection.request(
                    "GET",
                    path,
                    headers=headers,
                )

                response = connection.getresponse()

            except (TimeoutError, socket.timeout):
                raise ThreatLensTimeoutError() from None

            except (
                ConnectionError,
                ConnectionResetError,
                BrokenPipeError,
                http.client.RemoteDisconnected,
            ):
                raise ThreatLensError(
                    "ThreatLens connection failed"
                ) from None

            except OSError as exc:
                # Some socket/network failures surface as OSError.
                # Do not blindly call every OSError a timeout.
                if isinstance(exc, socket.timeout):
                    raise ThreatLensTimeoutError() from None

                raise ThreatLensError(
                    "ThreatLens connection failed"
                ) from None

            # --------------------------------------------------------
            # Apply read timeout after the HTTP response headers arrive.
            # --------------------------------------------------------

            if (
                response.fp is not None
                and hasattr(response.fp, "raw")
                and hasattr(response.fp.raw, "_sock")
            ):
                try:
                    response.fp.raw._sock.settimeout(
                        self.settings.threatlens_read_timeout_seconds
                    )
                except (AttributeError, OSError):
                    # If the underlying implementation doesn't expose
                    # the socket, continue using the connection's timeout.
                    pass

            # --------------------------------------------------------
            # HTTP status handling
            # --------------------------------------------------------

            if response.status in {401, 403}:
                raise ThreatLensAuthenticationError()

            if response.status == 404:
                raise ThreatLensNotFoundError()

            if response.status < 200 or response.status >= 300:
                raise ThreatLensError(
                    f"ThreatLens returned HTTP {response.status}"
                )

            # --------------------------------------------------------
            # Response body
            # --------------------------------------------------------

            try:
                body = response.read(MAX_RESPONSE_BYTES + 1)

            except (TimeoutError, socket.timeout):
                raise ThreatLensTimeoutError() from None

            except OSError as exc:
                if isinstance(exc, socket.timeout):
                    raise ThreatLensTimeoutError() from None

                raise ThreatLensError(
                    "ThreatLens response could not be read"
                ) from None

            if len(body) > MAX_RESPONSE_BYTES:
                raise ThreatLensMalformedResponseError(
                    "response exceeds size limit"
                )

            # --------------------------------------------------------
            # JSON parsing + schema validation
            # --------------------------------------------------------

            try:
                payload = json.loads(body)

                if (
                    not isinstance(payload, dict)
                    or not isinstance(payload.get("alert"), dict)
                ):
                    raise ThreatLensMalformedResponseError()

                result = ThreatLensAlertResponse.model_validate(
                    payload["alert"]
                )

            except ThreatLensMalformedResponseError:
                raise

            except (
                json.JSONDecodeError,
                ValidationError,
                TypeError,
            ):
                raise ThreatLensMalformedResponseError() from None

            # --------------------------------------------------------
            # Identifier integrity check
            # --------------------------------------------------------

            if result.identifier != alert_id:
                raise ThreatLensMalformedResponseError(
                    "alert identifier does not match request"
                )

            return result

        # ------------------------------------------------------------
        # IMPORTANT:
        #
        # Never convert an existing ThreatLensError into a timeout.
        #
        # This preserves:
        #   - authentication errors
        #   - not-found errors
        #   - malformed responses
        #   - generic HTTP/integration errors
        #
        # Only actual timeout exceptions should become
        # ThreatLensTimeoutError.
        # ------------------------------------------------------------

        except ThreatLensError:
            raise

        except (TimeoutError, socket.timeout):
            raise ThreatLensTimeoutError() from None

        except (
            ConnectionError,
            ConnectionResetError,
            BrokenPipeError,
            http.client.RemoteDisconnected,
        ):
            raise ThreatLensError(
                "ThreatLens connection failed"
            ) from None

        except OSError as exc:
            if isinstance(exc, socket.timeout):
                raise ThreatLensTimeoutError() from None

            raise ThreatLensError(
                "ThreatLens connection failed"
            ) from None

        finally:
            connection.close()

    def to_investigation_request(
        self,
        alert: ThreatLensAlertResponse,
    ) -> InvestigationRequest:
        metadata = dict(alert.metadata)
        raw_event = dict(alert.raw_event)

        # ------------------------------------------------------------
        # Asset extraction
        # ------------------------------------------------------------

        asset_data = (
            alert.asset
            or raw_event.get("asset")
            or metadata.get("asset")
            or {}
        )

        asset = (
            Asset.model_validate(
                {
                    "hostname": (
                        asset_data.get("hostname")
                        or metadata.get("hostname")
                    ),
                    "ip": (
                        asset_data.get("ip")
                        or metadata.get("ip")
                    ),
                    "url": (
                        asset_data.get("url")
                        or metadata.get("url")
                    ),
                }
            )
            if isinstance(asset_data, dict)
            else None
        )

        # ------------------------------------------------------------
        # Evidence
        # ------------------------------------------------------------

        evidence = dict(raw_event)

        evidence.setdefault(
            "threatlens_metadata",
            metadata,
        )

        # ------------------------------------------------------------
        # Finding
        # ------------------------------------------------------------

        finding_data: dict[str, Any] = {
            "type": (
                alert.category
                or raw_event.get("type")
                or "unknown"
            ),
            "title": (
                raw_event.get("title")
                or alert.category
                or "ThreatLens alert"
            ),
            "severity": alert.severity.value,
            "evidence": evidence,
            "category": alert.category,
        }

        for key in (
            "port",
            "protocol",
            "url",
            "ip",
        ):
            if key in raw_event:
                finding_data[key] = raw_event[key]

        # ------------------------------------------------------------
        # Investigation context
        # ------------------------------------------------------------

        context_data = {
            "historical_alerts": [],
            "related_findings": [],
            "asset_inventory": None,
            **metadata,
        }

        return InvestigationRequest(
            alert_id=alert.identifier,
            source=alert.source,
            timestamp=alert.timestamp,
            asset=asset,
            finding=Finding.model_validate(finding_data),
            context=AlertContext.model_validate(context_data),
            mitre_attack=(
                raw_event.get(
                    "mitre_attack",
                    metadata.get("mitre_attack", []),
                )
                or []
            ),
        )
