from typing import Any

from app.config import Settings
from app.llm.openai_compatible import OpenAICompatibleReasoner


class GroqReasoner(OpenAICompatibleReasoner):
    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        super().__init__("groq", settings.groq_api_key, settings.groq_base_url, settings.groq_model, settings.groq_connect_timeout_seconds, settings.groq_read_timeout_seconds, settings.llm_max_input_bytes, settings.llm_max_output_tokens, client)
