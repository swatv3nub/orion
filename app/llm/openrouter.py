from typing import Any

from app.config import Settings
from app.llm.openai_compatible import OpenAICompatibleReasoner


class OpenRouterReasoner(OpenAICompatibleReasoner):
    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        super().__init__("openrouter", settings.openrouter_api_key, settings.openrouter_base_url, settings.openrouter_model, settings.openrouter_connect_timeout_seconds, settings.openrouter_read_timeout_seconds, settings.llm_max_input_bytes, settings.llm_max_output_tokens, client)
