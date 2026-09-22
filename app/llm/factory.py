from app.config import Settings
from app.llm.base import LLMError, LLMReasoner
from app.llm.groq import GroqReasoner
from app.llm.openrouter import OpenRouterReasoner


class FallbackReasoner(LLMReasoner):
    def __init__(self, primary: LLMReasoner, fallback: LLMReasoner | None = None) -> None:
        self.primary = primary
        self.fallback = fallback
        self.provider, self.model = primary.provider, primary.model

    def analyze(self, *args):
        self.fallback_used = False
        self.primary_failure_reason = None
        try:
            return self._with_one_retry(*args)
        except LLMError as exc:
            if not exc.transient or self.fallback is None:
                raise
            self.fallback_used = True
            self.primary_failure_reason = exc.code
            try:
                result = self.fallback.analyze(*args)
                self.provider, self.model = self.fallback.provider, self.fallback.model
                return result
            except LLMError:
                self.provider, self.model = self.fallback.provider, self.fallback.model
                raise

    def _with_one_retry(self, *args):
        try:
            return self.primary.analyze(*args)
        except LLMError as exc:
            if not exc.transient:
                raise
            return self.primary.analyze(*args)


def create_reasoner(settings: Settings) -> LLMReasoner | None:
    if settings.llm_provider == "openrouter":
        return OpenRouterReasoner(settings) if settings.openrouter_api_key and settings.openrouter_model else None
    if settings.llm_provider == "groq" and settings.groq_api_key:
        return FallbackReasoner(GroqReasoner(settings), OpenRouterReasoner(settings) if settings.openrouter_api_key and settings.openrouter_model else None)
    return None
