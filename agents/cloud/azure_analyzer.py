"""Agente Analizador Azure."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class AzureAnalyzerAgent(BaseCloudAgent):
    name = "AzureAnalyzerAgent"
    description = "Análisis de seguridad en Microsoft Azure — VMs, AKS, Azure AD, Storage, NSG"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "Azure"
    tags = ["azure", "microsoft", "cloud", "azuread", "aks"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador Azure del AI-SOC. Analizas seguridad en Microsoft Azure:
- Azure AD: usuarios, grupos, aplicaciones, Conditional Access, MFA
- VMs: NSGs, Just-in-Time access, disk encryption, extensions
- Storage Accounts: public access, HTTPS only, soft delete
- AKS: RBAC, policies, network policies
- Azure Policy: compliance state, exemptions
- Defender for Cloud: secure score, recommendations
- Activity Logs: operaciones sospechosas, creación de recursos
- Key Vault: access policies, logging, soft delete
- App Service: authentication, TLS, network restrictions

Responde en JSON: risk_score, subscription, service_findings, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad de la suscripción Azure:

SUSCRIPCIÓN: {data.get('subscription_id', 'unknown')}
TENANT: {data.get('tenant_id', 'unknown')}
SECURE SCORE: {data.get('secure_score', 'unknown')}

RECURSOS Y CONFIGURACIONES:
{json.dumps(data.get('resources', {}), indent=2, default=str)[:3000]}

DEFENDER RECOMMENDATIONS:
{json.dumps(data.get('defender_recommendations', [])[:15], indent=2, default=str)[:1500]}

Identifica riesgos críticos en la suscripción Azure."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "service_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo Azure"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.83),
                affected_assets=[data.get("subscription_id", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("service_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.83,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
