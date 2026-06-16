"""Motor de IA multi-proveedor para el AI-SOC."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class AIProviderType(str, Enum):
    # Cloud APIs
    ANTHROPIC = "anthropic"          # Claude (Opus, Sonnet, Haiku)
    OPENAI = "openai"                # GPT-4o, GPT-4, GPT-3.5
    GEMINI = "gemini"                # Google Gemini Pro / Ultra
    AZURE_OPENAI = "azure_openai"    # Azure OpenAI Service
    AWS_BEDROCK = "aws_bedrock"      # Amazon Bedrock (Claude, Llama, Titan)
    MISTRAL = "mistral"              # Mistral Large / Small
    GROQ = "groq"                    # Groq (LPU — Llama, Mixtral)
    COHERE = "cohere"                # Cohere Command R+
    TOGETHER = "together"            # Together AI (open models)
    PERPLEXITY = "perplexity"        # Perplexity Online LLMs
    # Local inference
    OLLAMA = "ollama"                # Ollama (local, any model)
    LM_STUDIO = "lm_studio"         # LM Studio (OpenAI-compatible)
    VLLM = "vllm"                    # vLLM server (OpenAI-compatible)
    LLAMACPP = "llamacpp"            # llama.cpp server


class AIMessage:
    """Respuesta normalizada de cualquier proveedor."""

    def __init__(self, content: str, model: str, provider: str,
                 input_tokens: int = 0, output_tokens: int = 0) -> None:
        self.content = content
        self.model = model
        self.provider = provider
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens

    def __str__(self) -> str:
        return self.content


class AIProvider(ABC):
    """Interfaz base para todos los proveedores de IA."""

    provider_type: AIProviderType

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self._log = structlog.get_logger(self.__class__.__name__)

    @abstractmethod
    async def complete(
        self,
        user_prompt: str,
        system_prompt: str = "",
        max_tokens: int = 4096,
        temperature: float = 0.1,
    ) -> AIMessage:
        """Genera una respuesta dado un prompt."""
        ...

    @property
    def name(self) -> str:
        return self.provider_type.value


# ---------------------------------------------------------------------------
# Anthropic
# ---------------------------------------------------------------------------

class AnthropicProvider(AIProvider):
    provider_type = AIProviderType.ANTHROPIC

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        import anthropic as _anthropic
        self._client = _anthropic.AsyncAnthropic(api_key=config["api_key"])

    async def complete(self, user_prompt: str, system_prompt: str = "",
                       max_tokens: int = 4096, temperature: float = 0.1) -> AIMessage:
        import anthropic as _anthropic
        model = self.config.get("model", "claude-opus-4-8")
        kwargs: dict[str, Any] = dict(
            model=model, max_tokens=max_tokens,
            messages=[{"role": "user", "content": user_prompt}],
        )
        if system_prompt:
            kwargs["system"] = system_prompt
        resp = await self._client.messages.create(**kwargs)
        usage = resp.usage
        return AIMessage(
            content=resp.content[0].text, model=model, provider=self.name,
            input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
        )


# ---------------------------------------------------------------------------
# OpenAI  (also used by Azure OpenAI, LM Studio, vLLM, llama.cpp)
# ---------------------------------------------------------------------------

class OpenAIProvider(AIProvider):
    provider_type = AIProviderType.OPENAI

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        from openai import AsyncOpenAI
        self._client = AsyncOpenAI(
            api_key=config.get("api_key", "nokey"),
            base_url=config.get("base_url"),  # None → default
        )

    async def complete(self, user_prompt: str, system_prompt: str = "",
                       max_tokens: int = 4096, temperature: float = 0.1) -> AIMessage:
        model = self.config.get("model", "gpt-4o")
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        resp = await self._client.chat.completions.create(
            model=model, messages=messages,
            max_tokens=max_tokens, temperature=temperature,
        )
        usage = resp.usage
        return AIMessage(
            content=resp.choices[0].message.content or "",
            model=model, provider=self.name,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )


class AzureOpenAIProvider(OpenAIProvider):
    provider_type = AIProviderType.AZURE_OPENAI

    def __init__(self, config: dict[str, Any]) -> None:
        from openai import AsyncAzureOpenAI
        AIProvider.__init__(self, config)
        self._client = AsyncAzureOpenAI(
            api_key=config["api_key"],
            azure_endpoint=config["endpoint"],
            api_version=config.get("api_version", "2024-02-01"),
        )


class OllamaProvider(OpenAIProvider):
    """Ollama expone una API OpenAI-compatible en localhost."""
    provider_type = AIProviderType.OLLAMA

    def __init__(self, config: dict[str, Any]) -> None:
        config.setdefault("base_url", "http://localhost:11434/v1")
        config.setdefault("api_key", "ollama")
        super().__init__(config)


class LMStudioProvider(OpenAIProvider):
    """LM Studio expone una API OpenAI-compatible."""
    provider_type = AIProviderType.LM_STUDIO

    def __init__(self, config: dict[str, Any]) -> None:
        config.setdefault("base_url", "http://localhost:1234/v1")
        config.setdefault("api_key", "lmstudio")
        super().__init__(config)


class VLLMProvider(OpenAIProvider):
    """vLLM server con API OpenAI-compatible."""
    provider_type = AIProviderType.VLLM

    def __init__(self, config: dict[str, Any]) -> None:
        config.setdefault("api_key", "vllm")
        super().__init__(config)


class LlamaCppProvider(OpenAIProvider):
    """llama.cpp server con API OpenAI-compatible."""
    provider_type = AIProviderType.LLAMACPP

    def __init__(self, config: dict[str, Any]) -> None:
        config.setdefault("base_url", "http://localhost:8080/v1")
        config.setdefault("api_key", "llamacpp")
        super().__init__(config)


# ---------------------------------------------------------------------------
# Google Gemini
# ---------------------------------------------------------------------------

class GeminiProvider(AIProvider):
    provider_type = AIProviderType.GEMINI

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        import google.generativeai as genai
        genai.configure(api_key=config["api_key"])
        model_name = config.get("model", "gemini-1.5-pro")
        self._model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=None,
        )
        self._model_name = model_name

    async def complete(self, user_prompt: str, system_prompt: str = "",
                       max_tokens: int = 4096, temperature: float = 0.1) -> AIMessage:
        import google.generativeai as genai
        if system_prompt:
            self._model = genai.GenerativeModel(
                model_name=self._model_name,
                system_instruction=system_prompt,
            )
        full_prompt = user_prompt
        resp = await asyncio.to_thread(
            self._model.generate_content,
            full_prompt,
            generation_config={"max_output_tokens": max_tokens, "temperature": temperature},
        )
        usage = getattr(resp, "usage_metadata", None)
        return AIMessage(
            content=resp.text, model=self._model_name, provider=self.name,
            input_tokens=getattr(usage, "prompt_token_count", 0),
            output_tokens=getattr(usage, "candidates_token_count", 0),
        )


# ---------------------------------------------------------------------------
# AWS Bedrock
# ---------------------------------------------------------------------------

class AWSBedrockProvider(AIProvider):
    provider_type = AIProviderType.AWS_BEDROCK

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        import boto3
        self._client = boto3.client(
            "bedrock-runtime",
            region_name=config.get("region", "us-east-1"),
            aws_access_key_id=config.get("access_key_id"),
            aws_secret_access_key=config.get("secret_access_key"),
        )
        self._model_id = config.get("model_id", "anthropic.claude-opus-4-8-v1:0")

    async def complete(self, user_prompt: str, system_prompt: str = "",
                       max_tokens: int = 4096, temperature: float = 0.1) -> AIMessage:
        import json as _json
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        if system_prompt:
            body["system"] = system_prompt
        resp = await asyncio.to_thread(
            self._client.invoke_model,
            modelId=self._model_id,
            body=_json.dumps(body),
            contentType="application/json",
        )
        result = _json.loads(resp["body"].read())
        return AIMessage(
            content=result["content"][0]["text"],
            model=self._model_id, provider=self.name,
            input_tokens=result.get("usage", {}).get("input_tokens", 0),
            output_tokens=result.get("usage", {}).get("output_tokens", 0),
        )


# ---------------------------------------------------------------------------
# Mistral
# ---------------------------------------------------------------------------

class MistralProvider(AIProvider):
    provider_type = AIProviderType.MISTRAL

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        from mistralai import Mistral
        self._client = Mistral(api_key=config["api_key"])
        self._model = config.get("model", "mistral-large-latest")

    async def complete(self, user_prompt: str, system_prompt: str = "",
                       max_tokens: int = 4096, temperature: float = 0.1) -> AIMessage:
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        resp = await self._client.chat.complete_async(
            model=self._model, messages=messages,
            max_tokens=max_tokens, temperature=temperature,
        )
        usage = resp.usage
        return AIMessage(
            content=resp.choices[0].message.content or "",
            model=self._model, provider=self.name,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )


# ---------------------------------------------------------------------------
# Groq
# ---------------------------------------------------------------------------

class GroqProvider(AIProvider):
    provider_type = AIProviderType.GROQ

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        from groq import AsyncGroq
        self._client = AsyncGroq(api_key=config["api_key"])
        self._model = config.get("model", "llama-3.3-70b-versatile")

    async def complete(self, user_prompt: str, system_prompt: str = "",
                       max_tokens: int = 4096, temperature: float = 0.1) -> AIMessage:
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        resp = await self._client.chat.completions.create(
            model=self._model, messages=messages,
            max_tokens=max_tokens, temperature=temperature,
        )
        usage = resp.usage
        return AIMessage(
            content=resp.choices[0].message.content or "",
            model=self._model, provider=self.name,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
        )


# ---------------------------------------------------------------------------
# Cohere
# ---------------------------------------------------------------------------

class CohereProvider(AIProvider):
    provider_type = AIProviderType.COHERE

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        import cohere
        self._client = cohere.AsyncClient(api_key=config["api_key"])
        self._model = config.get("model", "command-r-plus")

    async def complete(self, user_prompt: str, system_prompt: str = "",
                       max_tokens: int = 4096, temperature: float = 0.1) -> AIMessage:
        preamble = system_prompt if system_prompt else None
        resp = await self._client.chat(
            model=self._model, message=user_prompt,
            preamble=preamble, max_tokens=max_tokens, temperature=temperature,
        )
        usage = getattr(resp, "meta", None)
        tokens = getattr(usage, "tokens", None) if usage else None
        return AIMessage(
            content=resp.text, model=self._model, provider=self.name,
            input_tokens=getattr(tokens, "input_tokens", 0) if tokens else 0,
            output_tokens=getattr(tokens, "output_tokens", 0) if tokens else 0,
        )


# ---------------------------------------------------------------------------
# Together AI
# ---------------------------------------------------------------------------

class TogetherProvider(OpenAIProvider):
    """Together AI usa API OpenAI-compatible."""
    provider_type = AIProviderType.TOGETHER

    def __init__(self, config: dict[str, Any]) -> None:
        config.setdefault("base_url", "https://api.together.xyz/v1")
        config.setdefault("model", "meta-llama/Llama-3.3-70B-Instruct-Turbo")
        super().__init__(config)


# ---------------------------------------------------------------------------
# Perplexity
# ---------------------------------------------------------------------------

class PerplexityProvider(OpenAIProvider):
    """Perplexity usa API OpenAI-compatible."""
    provider_type = AIProviderType.PERPLEXITY

    def __init__(self, config: dict[str, Any]) -> None:
        config.setdefault("base_url", "https://api.perplexity.ai")
        config.setdefault("model", "llama-3.1-sonar-large-128k-online")
        super().__init__(config)
