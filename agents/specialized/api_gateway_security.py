"""Agente Especialista en Seguridad de API Gateway."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class APIGatewaySecurityAgent(BaseAgent):
    name = "APIGatewaySecurityAgent"
    description = "Especialista en seguridad de APIs — OWASP API Top 10, JWT, OAuth, GraphQL, rate limiting"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.HIGH
    tags = ["api-security", "api-gateway", "rest", "graphql", "oauth", "jwt", "rate-limiting"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad de API Gateway del AI-SOC. Proteges APIs y microservicios:

Amenazas OWASP API Top 10:
- API1: Broken Object Level Authorization (BOLA/IDOR): acceso a recursos de otros usuarios
- API2: Broken Authentication: tokens JWT débiles, OAuth misconfigured
- API3: Broken Object Property Level Auth: mass assignment, exposición de campos sensibles
- API4: Unrestricted Resource Consumption: DoS por abuso de endpoints costosos
- API5: Broken Function Level Authorization: acceso a funciones admin
- API6: Unrestricted Access to Sensitive Business Flows: abuso de lógica de negocio
- API7: Server Side Request Forgery (SSRF): redirección a servicios internos
- API8: Security Misconfiguration: CORS abierto, errores verbosos, debug expuesto
- API9: Improper Inventory Management: shadow APIs, endpoints no documentados
- API10: Unsafe Consumption of APIs: dependencias de APIs externas no validadas

Vulnerabilidades adicionales:
- JWT: algorithm confusion (alg:none), weak secrets, no expiration
- GraphQL: introspection abuse, query depth attacks, batching attacks
- gRPC: reflection enabled, insecure channels
- Rate limiting bypass: IP rotation, slowloris, distributed abuse
- API key exposure en logs, URLs, repositorios públicos

Responde en JSON: risk_score, api_vuln_type, affected_endpoints, data_exposure_risk, auth_weakness, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del API Gateway:

API GATEWAY: {data.get('gateway_name', 'unknown')}
ENDPOINTS AFECTADOS: {data.get('affected_endpoints', [])}
TIPO DE AMENAZA: {data.get('threat_type', 'unknown')}
AUTH METHOD: {data.get('auth_method', 'unknown')}

LOGS DE ACCESO:
{json.dumps(data.get('access_logs', [])[:20], indent=2, default=str)[:2000]}

ANOMALÍAS DETECTADAS:
{json.dumps(data.get('anomalies', [])[:10], indent=2, default=str)[:1000]}

RATE LIMIT VIOLATIONS: {data.get('rate_limit_violations', 0)}
AUTENTICACIÓN FALLIDA: {data.get('auth_failures', 0)}

Evalúa las vulnerabilidades de API y genera el plan de remediación."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Vulnerabilidad de API Detectada"),
                description=a.get("description", ""),
                severity=Severity[a.get("severity", "HIGH")],
                category=ThreatCategory.WEB_ATTACK,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "api_vuln_type": result.get("api_vuln_type"),
                "affected_endpoints": result.get("affected_endpoints"),
                "data_exposure_risk": result.get("data_exposure_risk"),
                "auth_weakness": result.get("auth_weakness"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
