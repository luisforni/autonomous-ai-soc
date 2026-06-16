"""Agente Security Scorecard."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis


class SecurityScorecardAgent(BaseAgent):
    name = "SecurityScorecardAgent"
    description = "Scorecard de seguridad organizacional — puntuación por dominio, benchmarking"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.LOW
    tags = ["scorecard", "security-rating", "benchmarking", "posture", "assessment"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Security Scorecard del AI-SOC. Produces puntuaciones de seguridad:

Dominios evaluados (similar a NIST CSF):
1. Identify (ID): inventario de activos, gestión de riesgos
2. Protect (PR): controles de acceso, formación, datos
3. Detect (DE): monitoreo, detección de anomalías
4. Respond (RS): respuesta a incidentes, comunicaciones
5. Recover (RC): recuperación, mejoras

Escala: A (90-100), B (75-89), C (60-74), D (45-59), F (<45)

Responde en JSON: overall_score, grade, domain_scores, benchmark_comparison, trend, top_improvements, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera el Security Scorecard:

ORGANIZACIÓN: {data.get('organization', 'unknown')}
SECTOR: {data.get('sector', 'unknown')}
TAMAÑO: {data.get('size', 'mediana empresa')}

DATOS POR DOMINIO:
{json.dumps(data.get('domain_data', {}), indent=2, default=str)[:3000]}

BENCHMARK DEL SECTOR: {data.get('sector_benchmark', {})}
SCORECARD ANTERIOR: {data.get('previous_scorecard', {})}

Genera la puntuación y el plan de mejora."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"overall_score": 50, "grade": "C", "domain_scores": {}, "top_improvements": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"score": result.get("overall_score"), "grade": result.get("grade"), "domains": result.get("domain_scores")}],
            alerts=[],
            iocs=[],
            risk_score=float(10 - result.get("overall_score", 50) / 10),
            confidence=0.85,
            recommendations=result.get("top_improvements", []),
            raw_ai_response=response,
        )
