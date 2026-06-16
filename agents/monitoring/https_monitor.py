"""Agente Monitor HTTPS — inspección de tráfico web."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class HTTPSMonitorAgent(BaseAgent):
    name = "HTTPSMonitorAgent"
    description = "Monitoreo e inspección de tráfico HTTP/HTTPS — detección de ataques web"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["http", "https", "web", "waf", "attacks"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor HTTP/HTTPS del AI-SOC. Analizas tráfico web para detectar:
- SQL Injection, XSS, CSRF, XXE, SSRF
- Ataques de directorio traversal y LFI/RFI
- Intentos de webshell upload y RCE
- Scraping agresivo y bots maliciosos
- Exfiltración de datos vía HTTP
- Bypass de WAF y técnicas de evasión
- APIs mal configuradas expuestas

Responde en JSON: risk_score, http_stats, attacks_detected, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las siguientes peticiones HTTP:

PETICIONES:
{json.dumps(data.get('requests', [])[:100], indent=2, default=str)[:4000]}

RESPUESTAS ANÓMALAS: {data.get('error_responses', [])}
SERVIDOR: {data.get('server', 'desconocido')}
WAF ACTIVO: {data.get('waf_enabled', False)}

Detecta ataques web y actividades maliciosas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Ataque Web Detectado"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.INJECTION,
                confidence=a.get("confidence", 0.75),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("attacks_detected", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.83,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
