"""Agente Tracker de KPIs."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis


class KPITrackerAgent(BaseAgent):
    name = "KPITrackerAgent"
    description = "Seguimiento de KPIs de seguridad — métricas, tendencias, alertas de degradación"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.LOW
    tags = ["kpi", "metrics", "tracking", "security-program", "performance"]

    def _build_system_prompt(self) -> str:
        return """Eres el Tracker de KPIs del AI-SOC. Monitorizas:
KPIs de seguridad:
- MTTD: Mean Time to Detect
- MTTR: Mean Time to Respond
- MTTC: Mean Time to Contain
- Alert fatigue ratio: alertas procesadas vs generadas
- False positive rate
- Incidents per month by severity
- Patch compliance rate
- Vulnerability density (vulns per asset)
- Security training completion rate
- Phishing simulation click rate

Responde en JSON: risk_score, kpi_dashboard, trending_kpis, degraded_kpis, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza los KPIs de seguridad:

PERIODO: {data.get('period', 'último mes')}
KPIs ACTUALES: {json.dumps(data.get('current_kpis', {}), indent=2, default=str)[:1500]}
KPIs ANTERIORES: {json.dumps(data.get('previous_kpis', {}), indent=2, default=str)[:1000]}
OBJETIVOS: {json.dumps(data.get('targets', {}), default=str)}

Identifica KPIs degradados y genera recomendaciones."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "degraded_kpis": [], "trending_kpis": [], "recommendations": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("degraded_kpis", []),
            alerts=[],
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
