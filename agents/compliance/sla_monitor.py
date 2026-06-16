"""Agente Monitor de SLA."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class SLAMonitorAgent(BaseAgent):
    name = "SLAMonitorAgent"
    description = "Monitoreo de SLAs de seguridad — tiempos de respuesta, cumplimiento contractual"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.MEDIUM
    tags = ["sla", "compliance", "metrics", "response-time", "contracts"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de SLA del AI-SOC. Vigilas el cumplimiento de acuerdos de servicio:
- Tiempo de respuesta inicial por severidad (Critical: 15min, High: 1h, Medium: 4h, Low: 24h)
- Tiempo de resolución por severidad
- Disponibilidad del servicio SOC (99.9% uptime)
- Tiempos de notificación a clientes
- SLA breach: alerta automática antes del vencimiento
- Reportes de cumplimiento de SLA para contratos

Responde en JSON: risk_score, sla_status, breached_slas, at_risk_slas, metrics, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Evalúa el cumplimiento de SLA:

CLIENTE: {data.get('client', 'unknown')}
PERIODO: {data.get('period', 'este mes')}

INCIDENTES ABIERTOS:
{json.dumps(data.get('open_incidents', [])[:20], indent=2, default=str)[:2000]}

SLAs DEFINIDOS: {data.get('sla_definitions', {})}
CUMPLIMIENTO ACTUAL: {data.get('current_compliance_pct', 0)}%

Identifica SLAs en riesgo de incumplimiento."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "sla_status": {}, "breached_slas": [], "alerts": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "SLA en Riesgo de Incumplimiento"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.COMPLIANCE,
                confidence=0.95,
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[x for f in ("breached_slas", "at_risk_slas") for x in (result.get(f) if isinstance(result.get(f), list) else [])],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.95,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
