"""Agente Analizador AWS."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class AWSAnalyzerAgent(BaseCloudAgent):
    name = "AWSAnalyzerAgent"
    description = "Análisis de seguridad completo en AWS — EC2, S3, IAM, VPC, Lambda"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "AWS"
    tags = ["aws", "ec2", "s3", "iam", "vpc", "lambda", "cloud"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador AWS del AI-SOC. Realizas análisis profundo de seguridad en AWS:

Servicios cubiertos:
- EC2: security groups, metadata service, IMDSv2, public IPs
- S3: bucket policies, ACLs, versioning, encryption, public access
- IAM: roles, policies, MFA, access keys age
- VPC: flow logs, NACLs, route tables, peering
- Lambda: permisos excesivos, variables de entorno con secrets
- RDS: public access, encryption, backup retention
- CloudTrail: habilitado, log file validation, multi-region
- Config: reglas de compliance, remediación automática
- GuardDuty, Security Hub, Inspector

Responde en JSON: risk_score, aws_account, service_findings, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad de la cuenta AWS:

CUENTA: {data.get('account_id', 'unknown')}
REGIÓN: {data.get('region', 'us-east-1')}

RECURSOS AWS:
{json.dumps(data.get('resources', {}), indent=2, default=str)[:3000]}

SECURITY HUB FINDINGS:
{json.dumps(data.get('security_hub', [])[:20], indent=2, default=str)[:1000]}

CONFIG RULES:
{json.dumps(data.get('config_rules', [])[:10], indent=2, default=str)[:500]}

Identifica los riesgos más críticos y genera plan de remediación."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "service_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo AWS"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("account_id", "unknown")],
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
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
