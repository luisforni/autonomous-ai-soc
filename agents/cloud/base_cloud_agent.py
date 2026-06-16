"""Clase base para agentes cloud."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class BaseCloudAgent(BaseAgent):
    """Base común para agentes cloud."""

    provider: str = "generic"

    def _build_system_prompt(self) -> str:
        return f"""Eres un agente experto en seguridad cloud para {self.provider} del AI-SOC.
Detectas amenazas, misconfiguraciones y actividades sospechosas en entornos cloud.
Responde en JSON: risk_score, cloud_findings, misconfigurations, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la siguiente actividad/configuración cloud ({self.provider}):

{json.dumps(data, indent=2, default=str)[:4000]}"""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "misconfigurations": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", f"Alerta {self.provider}"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.75),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        findings = [x for f in ("cloud_findings", "misconfigurations") for x in (result.get(f) if isinstance(result.get(f), list) else [])]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=findings,
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
