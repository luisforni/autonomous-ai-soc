"""Clase base para todos los agentes del AI-SOC."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

import structlog

from core.config import settings
from core.models import AgentAnalysis, Alert, IOC, Severity, ThreatCategory

logger = structlog.get_logger(__name__)


class AgentStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    ERROR = "error"
    DISABLED = "disabled"


class AgentPriority(int, Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class ThreatLevel(int, Enum):
    CRITICAL = 10
    HIGH = 8
    MEDIUM = 5
    LOW = 3
    INFO = 1


class BaseAgent(ABC):
    """Clase base para todos los agentes del AI-SOC."""

    name: str = "BaseAgent"
    description: str = "Agente base"
    version: str = "1.0.0"
    category: str = "general"
    priority: AgentPriority = AgentPriority.MEDIUM
    tags: list[str] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if "name" in cls.__dict__ and cls.name != "BaseAgent":
            from core.agent_registry import registry
            registry.register_class(cls)

    def __init__(self) -> None:
        self.id = str(uuid.uuid4())
        self.status = AgentStatus.IDLE
        self._log = structlog.get_logger(self.__class__.__name__)
        self._metrics: dict[str, Any] = {
            "analyses_run": 0,
            "alerts_generated": 0,
            "errors": 0,
            "total_execution_ms": 0,
        }

    @property
    def _provider(self):
        """Proveedor de IA activo (lazy — se resuelve en el primer uso)."""
        from core.provider_factory import get_provider
        return get_provider()

    @abstractmethod
    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        """Analiza los datos de entrada y retorna un análisis."""
        ...

    @abstractmethod
    def _build_system_prompt(self) -> str:
        """Construye el prompt de sistema para el agente."""
        ...

    @abstractmethod
    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        """Construye el prompt de usuario con los datos a analizar."""
        ...

    async def run_analysis(self, data: dict[str, Any]) -> AgentAnalysis:
        """Ejecuta el análisis con manejo de errores y métricas."""
        start_time = time.time()
        self.status = AgentStatus.RUNNING
        self._metrics["analyses_run"] += 1

        try:
            self._log.info("Starting analysis", agent=self.name, data_keys=list(data.keys()))
            analysis = await self.analyze(data)
            analysis.execution_time_ms = int((time.time() - start_time) * 1000)
            self._metrics["alerts_generated"] += len(analysis.alerts)
            self._metrics["total_execution_ms"] += analysis.execution_time_ms
            self._log.info(
                "Analysis complete",
                agent=self.name,
                alerts=len(analysis.alerts),
                risk_score=analysis.risk_score,
                execution_ms=analysis.execution_time_ms,
            )
            return analysis
        except Exception as e:
            self._metrics["errors"] += 1
            self._log.error("Analysis failed", agent=self.name, error=str(e))
            raise
        finally:
            self.status = AgentStatus.IDLE

    async def _query_ai(
        self,
        user_prompt: str,
        system_prompt: str | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Consulta al proveedor de IA activo con reintentos ante rate limits."""
        system = system_prompt or self._build_system_prompt()
        max_tok = max_tokens or settings.ai_max_tokens

        for attempt in range(settings.agent_retry_attempts):
            try:
                msg = await self._provider.complete(
                    user_prompt=user_prompt,
                    system_prompt=system,
                    max_tokens=max_tok,
                    temperature=settings.ai_temperature,
                )
                return msg.content
            except Exception as exc:
                exc_name = type(exc).__name__
                is_rate_limit = any(s in exc_name.lower() for s in ("ratelimit", "rate_limit", "429"))
                if attempt == settings.agent_retry_attempts - 1:
                    raise
                wait = settings.agent_retry_delay * (2 ** attempt) if is_rate_limit else settings.agent_retry_delay
                self._log.warning(f"AI query error, retrying in {wait}s", attempt=attempt, error=str(exc))
                await asyncio.sleep(wait)

        raise RuntimeError(f"AI query failed after {settings.agent_retry_attempts} attempts")

    def _create_alert(
        self,
        title: str,
        description: str,
        severity: Severity,
        category: ThreatCategory = ThreatCategory.UNKNOWN,
        iocs: list[IOC] | None = None,
        recommendations: list[str] | None = None,
        confidence: float = 0.7,
        affected_assets: list[str] | None = None,
    ) -> Alert:
        """Crea una alerta estandarizada."""
        return Alert(
            title=title,
            description=description,
            severity=severity,
            category=category,
            source_agent=self.name,
            iocs=iocs or [],
            recommendations=recommendations or [],
            confidence=confidence,
            affected_assets=affected_assets or [],
        )

    def get_metrics(self) -> dict[str, Any]:
        avg_time = (
            self._metrics["total_execution_ms"] / self._metrics["analyses_run"]
            if self._metrics["analyses_run"] > 0 else 0
        )
        return {
            **self._metrics,
            "agent_name": self.name,
            "agent_id": self.id,
            "status": self.status,
            "avg_execution_ms": avg_time,
        }

    def _parse_score(self, value: Any, default: float = 0.0) -> float:
        """Convert AI risk_score value to float, ignoring non-numeric responses."""
        try:
            return max(0.0, min(10.0, float(value)))
        except (TypeError, ValueError):
            return default

    def _parse_ai_json(self, response: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
        """Parse AI response as JSON dict. Returns default on any failure."""
        fallback: dict[str, Any] = default if default is not None else {}
        try:
            parsed = json.loads(response)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass
        # Try to extract a JSON object from the response (AI often wraps it in text)
        try:
            start = response.index('{')
            end = response.rindex('}') + 1
            parsed = json.loads(response[start:end])
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, json.JSONDecodeError):
            pass
        return fallback

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id[:8]} status={self.status}>"
