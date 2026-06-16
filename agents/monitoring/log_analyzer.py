"""Agente Analizador de Logs — análisis inteligente de logs de múltiples fuentes."""

from __future__ import annotations

import json
import re
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class LogAnalyzerAgent(BaseAgent):
    name = "LogAnalyzerAgent"
    description = "Análisis inteligente de logs de sistemas, aplicaciones y seguridad"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["logs", "analysis", "syslog", "application", "security"]

    LOG_PATTERNS = {
        "failed_login": r"(Failed|Invalid|failed login|authentication failure)",
        "privilege_escalation": r"(sudo|su |privilege|root|admin|elevated)",
        "file_access": r"(chmod|chown|access denied|permission denied)",
        "network_connection": r"(connect|connection|established|ESTABLISHED)",
        "process_creation": r"(exec|spawn|fork|CreateProcess)",
        "registry_modification": r"(RegSetValue|RegCreateKey|registry)",
        "data_access": r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE TABLE)",
    }

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Logs del AI-SOC — experto en análisis forense y detección de amenazas en logs.

Analiza logs de:
- Sistemas operativos (Linux syslog, Windows Event Log)
- Aplicaciones web (Apache, Nginx, IIS)
- Bases de datos (MySQL, PostgreSQL, Oracle, MSSQL)
- Firewalls y dispositivos de red
- Aplicaciones de negocio

Detecta:
- Intentos de intrusión y ataques
- Comportamiento anómalo de usuarios
- Accesos no autorizados
- Actividades maliciosas
- Errores de seguridad

Responde en JSON:
{
  "risk_score": float,
  "log_type": str,
  "anomalies": [{"pattern": str, "count": int, "severity": str, "examples": [str]}],
  "alerts": [{"title": str, "description": str, "severity": str, "category": str, "log_lines": [str], "recommendations": [str], "confidence": float}],
  "iocs": [{"type": str, "value": str, "confidence": float}],
  "statistics": {"total_lines": int, "error_lines": int, "warning_lines": int},
  "recommendations": [str]
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        logs = data.get("logs", "")
        if isinstance(logs, list):
            logs = "\n".join(logs[:500])

        return f"""Analiza los siguientes logs y detecta actividades maliciosas o sospechosas:

TIPO DE LOG: {data.get('log_type', 'desconocido')}
FUENTE: {data.get('source', 'desconocido')}
PERIODO: {data.get('time_range', 'último 1h')}

LOGS (últimas 500 líneas):
{logs[:5000]}

Identifica patrones de ataque, IOCs y genera alertas para cualquier actividad sospechosa."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        pre_findings = self._pre_analyze_logs(data.get("logs", ""))
        data["pre_analysis"] = pre_findings

        prompt = self._build_user_prompt(data)
        response = await self._query_ai(prompt)

        result = self._parse_ai_json(response, {"risk_score": 0, "anomalies": [], "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        for alert_data in result.get("alerts", []):
            alert = self._create_alert(
                title=alert_data.get("title", "Alerta de Log"),
                description=alert_data.get("description", ""),
                severity=Severity(alert_data.get("severity", "medium")),
                category=ThreatCategory(alert_data.get("category", "unknown")),
                confidence=alert_data.get("confidence", 0.7),
                recommendations=alert_data.get("recommendations", []),
            )
            alerts.append(alert)

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(
                    type=IOCType(ioc_data.get("type", "ip")),
                    value=ioc_data.get("value", ""),
                    confidence=ioc_data.get("confidence", 0.5),
                    source=self.name,
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        findings = result.get("anomalies", []) + pre_findings

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=findings,
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.8,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )

    def _pre_analyze_logs(self, logs: str | list) -> list[dict[str, Any]]:
        if isinstance(logs, list):
            text = "\n".join(logs)
        else:
            text = str(logs)

        findings = []
        for pattern_name, pattern in self.LOG_PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings.append({
                    "pattern": pattern_name,
                    "count": len(matches),
                    "severity": "medium",
                    "description": f"Patrón detectado: {pattern_name} ({len(matches)} ocurrencias)",
                })
        return findings
