"""Agente Monitor de Accesos Privilegiados (PAM)."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class PrivilegedAccessMonitorAgent(BaseAgent):
    name = "PrivilegedAccessMonitorAgent"
    description = "Monitoreo de accesos privilegiados (PAM) — cuentas admin, root, service accounts"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.CRITICAL
    tags = ["pam", "privileged", "admin", "root", "service-account"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor PAM del AI-SOC. Vigilas accesos de cuentas privilegiadas:
- Uso de cuentas root/Administrator fuera de mantenimientos
- Sesiones privilegiadas desde IPs no autorizadas
- Comandos peligrosos ejecutados por cuentas privilegiadas
- Acceso a datos sensibles por cuentas de servicio
- Sesiones privilegiadas muy largas o inusuales
- Bypass de políticas de acceso privilegiado

Responde en JSON: risk_score, privileged_sessions, high_risk_commands, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la siguiente actividad privilegiada:

CUENTA: {data.get('account', 'root')}
TIPO: {data.get('account_type', 'admin')}
SISTEMA: {data.get('system', 'unknown')}
HORA: {data.get('timestamp', 'unknown')}

SESIONES PRIVILEGIADAS:
{json.dumps(data.get('sessions', [])[:20], indent=2, default=str)[:2000]}

COMANDOS EJECUTADOS:
{json.dumps(data.get('commands', [])[:50], indent=2, default=str)[:2000]}

MANTENIMIENTOS PROGRAMADOS: {data.get('maintenance_windows', [])}

Detecta uso indebido de privilegios y accesos no autorizados."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "high_risk_commands": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Uso Indebido de Privilegios"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "critical")),
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("system", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("high_risk_commands", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
