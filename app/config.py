from __future__ import annotations

import os
from dataclasses import dataclass

MAX_STEPS = 5
MAX_CALLS = 10
MAX_RUNTIME = 60.0


@dataclass(frozen=True)
class Settings:
    max_investigation_steps: int = MAX_STEPS
    max_tool_calls: int = MAX_CALLS
    max_runtime_seconds: float = MAX_RUNTIME
    threatlens_base_url: str = ""
    threatlens_api_key: str = ""
    reconix_cloud_base_url: str = ""
    reconix_cloud_api_key: str = ""
    threatlens_connect_timeout_seconds: float = 5.0
    threatlens_read_timeout_seconds: float = 15.0
    reconix_connect_timeout_seconds: float = 5.0
    reconix_read_timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            max_investigation_steps=min(max(_integer("MAX_INVESTIGATION_STEPS", MAX_STEPS), 0), MAX_STEPS),
            max_tool_calls=min(max(_integer("MAX_TOOL_CALLS", MAX_CALLS), 0), MAX_CALLS),
            max_runtime_seconds=min(max(_number("MAX_RUNTIME_SECONDS", MAX_RUNTIME), 0.1), MAX_RUNTIME),
            threatlens_base_url=os.getenv("THREATLENS_BASE_URL", "").rstrip("/"),
            threatlens_api_key=os.getenv("THREATLENS_API_KEY", ""),
            reconix_cloud_base_url=os.getenv("RECONIX_CLOUD_BASE_URL", "").rstrip("/"),
            reconix_cloud_api_key=os.getenv("RECONIX_CLOUD_API_KEY", ""),
            threatlens_connect_timeout_seconds=max(_number("THREATLENS_CONNECT_TIMEOUT_SECONDS", 5.0), 0.1),
            threatlens_read_timeout_seconds=max(_number("THREATLENS_READ_TIMEOUT_SECONDS", 15.0), 0.1),
            reconix_connect_timeout_seconds=max(_number("RECONIX_CLOUD_CONNECT_TIMEOUT_SECONDS", 5.0), 0.1),
            reconix_read_timeout_seconds=max(_number("RECONIX_CLOUD_READ_TIMEOUT_SECONDS", 30.0), 0.1),
        )


def _integer(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _number(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
