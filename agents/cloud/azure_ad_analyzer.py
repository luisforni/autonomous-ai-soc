"""Agente Azure Active Directory Analyzer."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class AzureADAnalyzerAgent(BaseCloudAgent):
    name = "AzureADAnalyzerAgent"
    description = "Análisis de Azure Active Directory — usuarios, grupos, aplicaciones, Conditional Access"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "Azure"
    tags = ["azuread", "aad", "identity", "entra", "microsoft", "mfa"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Azure AD del AI-SOC. Detectas riesgos en identidades Azure:
- Usuarios sin MFA habilitado
- Roles de administrador global excesivos
- Aplicaciones con permisos excesivos
- Políticas de acceso condicional deficientes
- Sign-ins de riesgo (impossible travel, leaked credentials)
- Service principals con credenciales sin expiración
- Guest users con acceso excesivo
- Risky users y risky sign-ins de Identity Protection

Responde en JSON: risk_score, identity_findings, risky_users, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad de Azure AD:

TENANT: {data.get('tenant_id', 'unknown')}
USUARIOS TOTALES: {data.get('total_users', 0)}

USUARIOS RIESGOSOS:
{json.dumps(data.get('risky_users', [])[:20], indent=2, default=str)[:1500]}

SIGN-INS RIESGOSOS:
{json.dumps(data.get('risky_signins', [])[:20], indent=2, default=str)[:1500]}

POLÍTICAS CA:
{json.dumps(data.get('ca_policies', [])[:10], indent=2, default=str)[:1000]}

ADMINS GLOBALES: {data.get('global_admins', [])}
USUARIOS SIN MFA: {data.get('users_without_mfa', 0)}

Detecta compromisos de identidad y configuraciones inseguras."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "identity_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo Azure AD"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("identity_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
