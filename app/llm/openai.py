from typing import Any

from app.config import Settings
from app.llm.openai_compatible import OpenAICompatibleReasoner


class OpenAIReasoner(OpenAICompatibleReasoner):
    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        super().__init__(
            "openai", settings.openai_api_key, settings.openai_base_url, settings.openai_model,
            settings.openai_connect_timeout_seconds, settings.openai_read_timeout_seconds,
            settings.llm_max_input_bytes, settings.llm_max_output_tokens, client,
            reasoning_effort="low", use_max_completion_tokens=True,
        )
