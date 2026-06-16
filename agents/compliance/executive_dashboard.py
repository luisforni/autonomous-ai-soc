"""Agente Dashboard Ejecutivo."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis


class ExecutiveDashboardAgent(BaseAgent):
    name = "ExecutiveDashboardAgent"
    description = "Dashboard ejecutivo con KPIs, riesgo organizacional y tendencias"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.LOW
    tags = ["dashboard", "executive", "kpi", "risk", "metrics"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Dashboard Ejecutivo del AI-SOC. Produces métricas para C-suite:
- Security Posture Score (0-100)
- Incidents this month vs last month
- Mean Time to Detect (MTTD)
- Mean Time to Respond (MTTR)
- Critical vulnerabilities open
- Compliance score by framework
- Top threats this period
- Security investment ROI
- Risk trend (improving/degrading)

Responde en JSON: posture_score, trend, top_risks, key_metrics, board_summary, action_items."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera el dashboard ejecutivo:

CLIENTE: {data.get('client', 'unknown')}
PERIODO: {data.get('period', 'este mes')}

MÉTRICAS DEL PERIODO:
{json.dumps(data.get('metrics', {}), indent=2, default=str)[:2000]}

INCIDENTES: {json.dumps(data.get('incidents', [])[:10], default=str)[:500]}
VULNERABILIDADES ABIERTAS: {data.get('open_vulnerabilities', 0)}
COMPLIANCE SCORES: {data.get('compliance_scores', {})}

Genera un resumen ejecutivo conciso con las 3-5 métricas más importantes."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"posture_score": 0, "top_risks": [], "action_items": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("top_risks", []),
            alerts=[],
            iocs=[],
            risk_score=float(10 - result.get("posture_score", 50) / 10),
            confidence=0.88,
            recommendations=result.get("action_items", []),
            raw_ai_response=response,
        )
