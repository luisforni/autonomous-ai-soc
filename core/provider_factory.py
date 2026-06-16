"""Fábrica de proveedores de IA — crea el proveedor activo desde la configuración."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

import structlog

from core.ai_provider import (
    AIProvider,
    AIProviderType,
    AnthropicProvider,
    AWSBedrockProvider,
    AzureOpenAIProvider,
    CohereProvider,
    GeminiProvider,
    GroqProvider,
    LlamaCppProvider,
    LMStudioProvider,
    MistralProvider,
    OllamaProvider,
    OpenAIProvider,
    PerplexityProvider,
    TogetherProvider,
    VLLMProvider,
)

if TYPE_CHECKING:
    from core.config import Settings

logger = structlog.get_logger(__name__)

_PROVIDER_MAP: dict[AIProviderType, type[AIProvider]] = {
    AIProviderType.ANTHROPIC:   AnthropicProvider,
    AIProviderType.OPENAI:      OpenAIProvider,
    AIProviderType.GEMINI:      GeminiProvider,
    AIProviderType.AZURE_OPENAI: AzureOpenAIProvider,
    AIProviderType.AWS_BEDROCK: AWSBedrockProvider,
    AIProviderType.MISTRAL:     MistralProvider,
    AIProviderType.GROQ:        GroqProvider,
    AIProviderType.COHERE:      CohereProvider,
    AIProviderType.TOGETHER:    TogetherProvider,
    AIProviderType.PERPLEXITY:  PerplexityProvider,
    AIProviderType.OLLAMA:      OllamaProvider,
    AIProviderType.LM_STUDIO:   LMStudioProvider,
    AIProviderType.VLLM:        VLLMProvider,
    AIProviderType.LLAMACPP:    LlamaCppProvider,
}


def _build_config(settings: Settings) -> dict:
    """Extrae la configuración del proveedor activo desde Settings."""
    p = settings.ai_provider
    if p == AIProviderType.ANTHROPIC:
        return {"api_key": settings.anthropic_api_key, "model": settings.anthropic_model}
    if p == AIProviderType.OPENAI:
        return {"api_key": settings.openai_api_key, "model": settings.openai_model}
    if p == AIProviderType.AZURE_OPENAI:
        return {
            "api_key": settings.azure_openai_api_key,
            "endpoint": settings.azure_openai_endpoint,
            "api_version": settings.azure_openai_api_version,
            "model": settings.azure_openai_deployment,
        }
    if p == AIProviderType.GEMINI:
        return {"api_key": settings.gemini_api_key, "model": settings.gemini_model}
    if p == AIProviderType.AWS_BEDROCK:
        return {
            "access_key_id": settings.aws_access_key_id,
            "secret_access_key": settings.aws_secret_access_key,
            "region": settings.aws_default_region,
            "model_id": settings.bedrock_model_id,
        }
    if p == AIProviderType.MISTRAL:
        return {"api_key": settings.mistral_api_key, "model": settings.mistral_model}
    if p == AIProviderType.GROQ:
        return {"api_key": settings.groq_api_key, "model": settings.groq_model}
    if p == AIProviderType.COHERE:
        return {"api_key": settings.cohere_api_key, "model": settings.cohere_model}
    if p == AIProviderType.TOGETHER:
        return {"api_key": settings.together_api_key, "model": settings.together_model}
    if p == AIProviderType.PERPLEXITY:
        return {"api_key": settings.perplexity_api_key, "model": settings.perplexity_model}
    if p == AIProviderType.OLLAMA:
        return {"base_url": settings.ollama_base_url, "model": settings.ollama_model}
    if p == AIProviderType.LM_STUDIO:
        return {"base_url": settings.lm_studio_base_url, "model": settings.lm_studio_model}
    if p == AIProviderType.VLLM:
        return {"base_url": settings.vllm_base_url, "model": settings.vllm_model}
    if p == AIProviderType.LLAMACPP:
        return {"base_url": settings.llamacpp_base_url, "model": settings.llamacpp_model}
    raise ValueError(f"Proveedor desconocido: {p}")


@lru_cache(maxsize=1)
def get_provider() -> AIProvider:
    """Retorna la instancia singleton del proveedor activo."""
    from core.config import settings
    provider_cls = _PROVIDER_MAP[settings.ai_provider]
    config = _build_config(settings)
    logger.info("AI provider initialized", provider=settings.ai_provider.value)
    return provider_cls(config)


def reset_provider_cache() -> None:
    """Limpia el cache del proveedor (útil para tests)."""
    get_provider.cache_clear()
