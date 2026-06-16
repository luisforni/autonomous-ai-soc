"""Agente de Lecciones Aprendidas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis


class LessonsLearnedAgent(BaseAgent):
    name = "LessonsLearnedAgent"
    description = "Generación de lecciones aprendidas — mejoras de seguridad, capacitación, procedimientos"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.LOW
    tags = ["lessons-learned", "improvement", "training", "procedures", "security-program"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Lecciones Aprendidas del AI-SOC. Generas mejoras sistémicas:
- Qué funcionó bien y qué no en la respuesta
- Gaps tecnológicos: herramientas faltantes, cobertura insuficiente
- Gaps de proceso: procedimientos no documentados, falta de playbooks
- Gaps humanos: capacitación, comunicación, escalada
- Quick wins: mejoras de bajo costo/alta efectividad
- Roadmap de seguridad: mejoras a 30/60/90 días
- Actualización de runbooks y playbooks

Responde en JSON: lessons_learned, what_worked, what_failed, technology_gaps, process_gaps, human_gaps, improvement_roadmap, training_recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera lecciones aprendidas del incidente:

INCIDENTE: {data.get('incident_id', 'unknown')}
ANÁLISIS POST-INCIDENTE:
{json.dumps(data.get('post_incident_analysis', {}), indent=2, default=str)[:2000]}

MÉTRICAS:
- MTTD: {data.get('mttd_hours', 0)} horas
- MTTR: {data.get('mttr_hours', 0)} horas
- Impacto financiero estimado: USD {data.get('financial_impact', 0)}

FEEDBACK DEL EQUIPO: {data.get('team_feedback', [])}

Genera un plan de mejora concreto y accionable."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"lessons_learned": [], "improvement_roadmap": [], "training_recommendations": []})

        all_recommendations = (
            result.get("improvement_roadmap", []) +
            result.get("training_recommendations", [])
        )

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("lessons_learned", []),
            alerts=[],
            iocs=[],
            risk_score=0.0,
            confidence=0.85,
            recommendations=all_recommendations,
            raw_ai_response=response,
        )
