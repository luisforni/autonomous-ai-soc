"""Agente IAM Analyzer."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class IAMAnalyzerAgent(BaseCloudAgent):
    name = "IAMAnalyzerAgent"
    description = "Análisis de políticas IAM multi-cloud — permisos excesivos, least privilege"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "multi-cloud"
    tags = ["iam", "permissions", "least-privilege", "roles", "policies"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador IAM del AI-SOC. Evalúas políticas de identidad y acceso:
- Usuarios/roles con AdministratorAccess o equivalente sin necesidad
- Políticas inline vs managed
- Access keys sin rotar (>90 días)
- Usuarios sin MFA con acceso a consola
- Roles que pueden asumir cualquier servicio
- Cross-account trust relationships riesgosas
- Permisos de escritura a CloudTrail/GuardDuty/Config
- Service accounts con permisos excesivos en GCP/Azure

Responde en JSON: risk_score, iam_findings, privileged_principals, alerts, remediation."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las políticas IAM:

PROVEEDOR: {data.get('provider', 'AWS')}
CUENTA/PROYECTO: {data.get('account', 'unknown')}

USUARIOS IAM:
{json.dumps(data.get('users', [])[:20], indent=2, default=str)[:2000]}

ROLES:
{json.dumps(data.get('roles', [])[:20], indent=2, default=str)[:2000]}

POLÍTICAS PERSONALIZADAS:
{json.dumps(data.get('policies', [])[:10], indent=2, default=str)[:1000]}

Identifica violaciones del principio de mínimo privilegio."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iam_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo IAM"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                confidence=a.get("confidence", 0.88),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("iam_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("remediation", result.get("recommendations", [])),
            raw_ai_response=response,
        )
