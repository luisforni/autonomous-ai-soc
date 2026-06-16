"""Agente Monitor SIEM — correlación y análisis centralizado de eventos de seguridad."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class SIEMMonitorAgent(BaseAgent):
    name = "SIEMMonitorAgent"
    description = "Monitoreo central de eventos de seguridad con correlación avanzada"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.CRITICAL
    tags = ["siem", "monitoring", "correlation", "events"]

    def _build_system_prompt(self) -> str:
        return """Eres el agente Monitor SIEM del AI-SOC — un experto en correlación y análisis de eventos de seguridad.

Tu función es:
1. Correlacionar eventos de múltiples fuentes (firewalls, IDS/IPS, antivirus, servidores, aplicaciones)
2. Detectar patrones de ataque mediante correlación temporal y contextual
3. Identificar amenazas complejas que no son evidentes analizando eventos individuales
4. Mapear actividades maliciosas con el framework MITRE ATT&CK
5. Priorizar alertas según impacto y confianza

Responde SIEMPRE en formato JSON con la estructura:
{
  "risk_score": float (0-10),
  "findings": [{"type": str, "description": str, "severity": str, "evidence": [str]}],
  "alerts": [{"title": str, "description": str, "severity": str, "category": str, "mitre_tactics": [str], "affected_assets": [str], "recommendations": [str], "confidence": float}],
  "iocs": [{"type": str, "value": str, "confidence": float}],
  "correlation_patterns": [str],
  "recommendations": [str]
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza los siguientes eventos SIEM y detecta amenazas o patrones sospechosos:

EVENTOS:
{json.dumps(data.get('events', []), indent=2, default=str)}

CONTEXTO DEL CLIENTE:
- Sector: {data.get('sector', 'desconocido')}
- Activos críticos: {data.get('critical_assets', [])}
- Ventana temporal: {data.get('time_window', '1h')}
- Umbral de correlación: {data.get('correlation_threshold', 5)}

Correlaciona los eventos, detecta patrones de ataque y genera las alertas correspondientes."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        prompt = self._build_user_prompt(data)
        response = await self._query_ai(prompt)

        result = self._parse_ai_json(response, {"risk_score": 0, "findings": [], "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        for alert_data in result.get("alerts", []):
            alert = self._create_alert(
                title=alert_data.get("title", "Alerta SIEM"),
                description=alert_data.get("description", ""),
                severity=Severity(alert_data.get("severity", "medium")),
                category=ThreatCategory(alert_data.get("category", "unknown")),
                confidence=alert_data.get("confidence", 0.7),
                affected_assets=alert_data.get("affected_assets", []),
                recommendations=alert_data.get("recommendations", []),
            )
            alerts.append(alert)

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                ioc = IOC(
                    type=IOCType(ioc_data.get("type", "ip")),
                    value=ioc_data.get("value", ""),
                    confidence=ioc_data.get("confidence", 0.5),
                    source=self.name,
                )
                iocs.append(ioc)
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("findings", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
