from __future__ import annotations

import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import BaseModel, Field

from app.models import Evidence, ToolResult
from app.tools.base import InvestigationTool, safe_error

MAX_RESPONSE_BYTES = 1_000_000


class ThreatLensQueryRequest(BaseModel):
    alert_id: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:-]+$")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def query_json(tool: str, base_url: str, path: str, api_key: str, connect_timeout: float = 5.0, read_timeout: float = 15.0) -> ToolResult:
    if not base_url:
        return safe_error(tool, "denied", "Integration is not configured")
    started = time.monotonic()
    try:
        request = Request(f"{base_url}{path}", headers={"Accept": "application/json", **({"Authorization": f"Bearer {api_key}"} if api_key else {})})
        with build_opener(NoRedirect()).open(request, timeout=connect_timeout) as response:
            if response.fp is not None and hasattr(response.fp, "raw") and hasattr(response.fp.raw, "_sock"):
                response.fp.raw._sock.settimeout(read_timeout)
            payload = response.read(MAX_RESPONSE_BYTES + 1)
            if len(payload) > MAX_RESPONSE_BYTES:
                return safe_error(tool, "error", "Tool response exceeded size limit")
            data = json.loads(payload or b"{}")
            return ToolResult(tool=tool, status="success", data=data if isinstance(data, dict) else {"result": data}, metadata={"duration_ms": int((time.monotonic() - started) * 1000)})
    except HTTPError as exc:
        return safe_error(tool, "not_found" if exc.code == 404 else "error", f"Integration returned HTTP {exc.code}")
    except (TimeoutError, URLError, OSError, json.JSONDecodeError):
        return safe_error(tool, "timeout", "Integration request failed or timed out")
