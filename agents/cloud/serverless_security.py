"""Agente Serverless Security."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class ServerlessSecurityAgent(BaseCloudAgent):
    name = "ServerlessSecurityAgent"
    description = "Seguridad en arquitecturas serverless — Lambda, Cloud Functions, Azure Functions"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.MEDIUM
    provider = "multi-cloud"
    tags = ["serverless", "lambda", "cloud-functions", "faas", "security"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Seguridad Serverless del AI-SOC. Analizas funciones serverless:
- Funciones con permisos IAM excesivos
- Secrets en variables de entorno en texto plano
- Código con vulnerabilidades (OWASP)
- Timeouts muy largos (consumo de recursos)
- Función expuesta sin autenticación
- Dependencias con CVEs conocidos
- Event injection (SNS/SQS/API Gateway payload)
- Function poisoning y cold start attacks

Responde en JSON: risk_score, functions_analyzed, security_issues, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las funciones serverless:

PROVEEDOR: {data.get('provider', 'AWS Lambda')}
FUNCIONES:
{json.dumps(data.get('functions', [])[:20], indent=2, default=str)[:3000]}

Detecta riesgos de seguridad en las funciones serverless."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "security_issues": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo Serverless"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.78),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("security_issues", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.78,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
