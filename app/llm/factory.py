from app.config import Settings
from app.llm.base import LLMError, LLMReasoner
from app.llm.gemini import GeminiReasoner
from app.llm.openai import OpenAIReasoner
from app.llm.openrouter import OpenRouterReasoner


class FallbackReasoner(LLMReasoner):
    def __init__(self, primary: LLMReasoner, fallbacks: LLMReasoner | list[LLMReasoner] | None = None) -> None:
        self.primary = primary
        self.fallbacks = [fallbacks] if isinstance(fallbacks, LLMReasoner) else fallbacks or []
        self.fallback = self.fallbacks[0] if self.fallbacks else None
        self.provider, self.model = primary.provider, primary.model

    def analyze(self, *args):
        self.fallback_used = False
        self.primary_failure_reason = None
        self.provider, self.model = self.primary.provider, self.primary.model
        for index, reasoner in enumerate([self.primary, *self.fallbacks]):
            try:
                result = self._with_one_retry(reasoner, *args) if index == 0 else reasoner.analyze(*args)
                self.provider, self.model = reasoner.provider, reasoner.model
                return result
            except LLMError as exc:
                self.provider, self.model = reasoner.provider, reasoner.model
                if not exc.transient or index == len(self.fallbacks):
                    raise
                self.fallback_used = True
                if index == 0:
                    self.primary_failure_reason = exc.code
                continue
        raise LLMError("llm_error")

    def _with_one_retry(self, reasoner: LLMReasoner, *args):
        try:
            return reasoner.analyze(*args)
        except LLMError as exc:
            if not exc.transient:
                raise
            return reasoner.analyze(*args)


def create_reasoner(settings: Settings) -> LLMReasoner | None:
    openrouter = OpenRouterReasoner(settings) if settings.openrouter_api_key and settings.openrouter_model else None
    if settings.llm_provider == "openrouter":
        return openrouter
    openai = OpenAIReasoner(settings) if settings.openai_api_key and settings.openai_model else None
    if settings.llm_provider == "openai":
        return FallbackReasoner(openai, openrouter) if openai else None
    if settings.llm_provider == "gemini" and settings.gemini_api_key and settings.gemini_model:
        return FallbackReasoner(GeminiReasoner(settings), [item for item in (openai, openrouter) if item])
    return None
