"""Agente Monitor de Identidad y Acceso (IAM)."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class IdentityAccessMonitorAgent(BaseAgent):
    name = "IdentityAccessMonitorAgent"
    description = "Monitoreo de identidad y acceso — autenticación, autorización, anomalías de comportamiento"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["iam", "identity", "access", "ueba", "authentication"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor IAM/UEBA del AI-SOC. Detectas anomalías de identidad y acceso:
- Autenticaciones desde ubicaciones/dispositivos inusuales
- Escalada de privilegios no autorizada
- Account takeover y credential stuffing
- Acceso a recursos fuera del perfil habitual del usuario
- Múltiples fallos de autenticación seguidos de éxito
- Uso compartido de cuentas
- Cuentas de servicio usadas interactivamente

Responde en JSON: risk_score, user_behavior_analysis, anomalies, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la siguiente actividad de identidad y acceso:

USUARIO: {data.get('username', 'unknown')}
IP ORIGEN: {data.get('source_ip', 'unknown')}
UBICACIÓN: {data.get('location', 'unknown')}
DISPOSITIVO: {data.get('device', 'unknown')}

EVENTOS DE AUTENTICACIÓN:
{json.dumps(data.get('auth_events', [])[:50], indent=2, default=str)[:2000]}

ACCESOS A RECURSOS:
{json.dumps(data.get('resource_access', [])[:30], indent=2, default=str)[:2000]}

BASELINE DEL USUARIO: {json.dumps(data.get('user_baseline', {}), default=str)}

Detecta anomalías de comportamiento y posibles compromisos de cuenta."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "anomalies": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Anomalía de Identidad"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                confidence=a.get("confidence", 0.8),
                affected_assets=[data.get("username", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("anomalies", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.83,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
