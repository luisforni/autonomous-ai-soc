"""Agente Analizador de Syslogs."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class SyslogAnalyzerAgent(BaseAgent):
    name = "SyslogAnalyzerAgent"
    description = "Análisis especializado de syslogs de sistemas y dispositivos de red"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.MEDIUM
    tags = ["syslog", "logs", "network-devices", "cisco", "fortinet"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Syslogs del AI-SOC. Analizas syslogs de:
- Dispositivos de red (routers, switches Cisco, Juniper)
- Firewalls (Fortinet, Palo Alto, Check Point)
- Sistemas Linux/Unix
- Dispositivos IoT y OT
- Balanceadores de carga

Detectas:
- Cambios de configuración no autorizados
- Interfaces caídas sospechosamente
- Intentos de acceso no autorizado
- Tráfico bloqueado anómalo
- Fallos de autenticación

Responde en JSON: risk_score, device_summary, critical_events, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza los siguientes syslogs:

DISPOSITIVO: {data.get('device', 'unknown')} | TIPO: {data.get('device_type', 'unknown')}
IP: {data.get('device_ip', 'unknown')}

SYSLOGS:
{str(data.get('logs', ''))[:4000]}

NIVEL MÍNIMO: {data.get('min_severity', 'warning')}

Detecta eventos críticos y comportamiento anómalo del dispositivo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "critical_events": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Evento Crítico en Syslog"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.75),
                affected_assets=[data.get("device_ip", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("critical_events", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.8,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
