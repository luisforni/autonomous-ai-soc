"""Agente Puntuador de Riesgo."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis


class RiskScorerAgent(BaseAgent):
    name = "RiskScorerAgent"
    description = "Puntuación automática de riesgo organizacional — activos, amenazas, vulnerabilidades"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.MEDIUM
    tags = ["risk", "scoring", "assessment", "risk-management", "cyber-risk"]

    def _build_system_prompt(self) -> str:
        return """Eres el Puntuador de Riesgo del AI-SOC. Calculas el riesgo cibernético:
Risk = Threat × Vulnerability × Asset Value × (1 - Controls Effectiveness)

Evalúas:
- Activos críticos y su valor (datos, sistemas, reputación)
- Amenazas activas relevantes para el sector
- Vulnerabilidades explotables
- Efectividad de controles actuales
- Impacto financiero esperado (ALE: Annual Loss Expectancy)
- Riesgo residual vs riesgo aceptable

Responde en JSON: risk_score, risk_breakdown, top_risk_factors, ale_estimate, risk_appetite_comparison, alerts, risk_reduction_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Calcula el riesgo organizacional:

ORGANIZACIÓN: {data.get('organization', 'unknown')}
SECTOR: {data.get('sector', 'unknown')}
TAMAÑO: {data.get('size', 'mediana')}

ACTIVOS CRÍTICOS: {json.dumps(data.get('critical_assets', [])[:10], default=str)[:500]}
AMENAZAS ACTIVAS: {json.dumps(data.get('active_threats', [])[:10], default=str)[:500]}
VULNERABILIDADES ABIERTAS: {data.get('open_vulns', 0)}
CONTROLES IMPLEMENTADOS: {json.dumps(data.get('controls', [])[:10], default=str)[:500]}

RIESGO ACEPTABLE: {data.get('risk_appetite', 'medium')}

Calcula el riesgo y prioriza las acciones de reducción."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 5, "top_risk_factors": [], "risk_reduction_actions": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("top_risk_factors", []),
            alerts=[],
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score"), 5),
            confidence=0.82,
            recommendations=result.get("risk_reduction_actions", []),
            raw_ai_response=response,
        )
