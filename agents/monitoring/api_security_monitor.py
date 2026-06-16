"""Agente Monitor de Seguridad de APIs."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class APISecurityMonitorAgent(BaseAgent):
    name = "APISecurityMonitorAgent"
    description = "Monitoreo de seguridad de APIs REST/GraphQL — OWASP API Top 10"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["api", "rest", "graphql", "owasp", "security"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Seguridad de APIs del AI-SOC. Detectas amenazas OWASP API Top 10:
- API1: Broken Object Level Authorization
- API2: Broken Authentication
- API3: Broken Object Property Level Authorization
- API4: Unrestricted Resource Consumption
- API5: Broken Function Level Authorization
- API6: Unrestricted Access to Sensitive Business Flows
- API7: Server Side Request Forgery
- API8: Security Misconfiguration
- API9: Improper Inventory Management
- API10: Unsafe Consumption of APIs

Responde en JSON: risk_score, api_stats, vulnerabilities_found, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el siguiente tráfico de API:

ENDPOINTS ACCEDIDOS:
{json.dumps(data.get('endpoints', [])[:50], indent=2, default=str)[:3000]}

AUTENTICACIÓN: {data.get('auth_type', 'Bearer')}
RATE LIMIT ACTUAL: {data.get('rate_limit_hits', 0)}
ERRORES 401/403: {data.get('auth_errors', 0)}
ERRORES 500: {data.get('server_errors', 0)}

Detecta abusos de API, exposición de datos y accesos no autorizados."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "vulnerabilities_found": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Vulnerabilidad de API"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.75),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("vulnerabilities_found", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
