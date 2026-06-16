"""Agente Analizador Post-Incidente."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity


class PostIncidentAnalyzerAgent(BaseAgent):
    name = "PostIncidentAnalyzerAgent"
    description = "Análisis post-incidente — causa raíz, timeline completo, mejoras de seguridad"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.MEDIUM
    tags = ["post-incident", "root-cause", "timeline", "lessons", "report"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analista Post-Incidente del AI-SOC. Realizas análisis profundos:
- Causa raíz (5 Whys, Fishbone diagram)
- Timeline completo del incidente
- Vector de entrada inicial
- Dwell time (tiempo sin detectar)
- MTTD (Mean Time to Detect)
- MTTR (Mean Time to Respond)
- Impacto real (datos afectados, servicios caídos, costos)
- Gaps de detección identificados
- Recomendaciones de mejora priorizadas

Responde en JSON: risk_score, root_cause, timeline, metrics, detection_gaps, improvement_actions, executive_summary."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el incidente post-mortem:

INCIDENTE: {data.get('incident_id', 'unknown')}
TIPO: {data.get('incident_type', 'unknown')}
SEVERIDAD: {data.get('severity', 'unknown')}
DURACIÓN: {data.get('duration_hours', 0)} horas
DETECCIÓN: {data.get('detection_time', 'unknown')}
RESOLUCIÓN: {data.get('resolution_time', 'unknown')}

DATOS DEL INCIDENTE:
{json.dumps(data.get('incident_data', {}), indent=2, default=str)[:3000]}

IMPACTO EN NEGOCIO: {data.get('business_impact', {})}
ACCIONES TOMADAS: {data.get('response_actions', [])}

Genera el análisis post-incidente completo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "root_cause": "", "metrics": {}, "improvement_actions": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"root_cause": result.get("root_cause"), "metrics": result.get("metrics")}],
            alerts=[],
            iocs=[],
            risk_score=0.0,
            confidence=0.88,
            recommendations=result.get("improvement_actions", []),
            raw_ai_response=response,
        )
