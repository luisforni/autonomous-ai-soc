"""Agente Analizador GCP."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class GCPAnalyzerAgent(BaseCloudAgent):
    name = "GCPAnalyzerAgent"
    description = "Análisis de seguridad en Google Cloud Platform — GCE, GKE, IAM, Cloud Storage"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "GCP"
    tags = ["gcp", "google-cloud", "gke", "bigquery", "cloud"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador GCP del AI-SOC. Analizas seguridad en Google Cloud:
- IAM: bindings excesivos, service accounts, primitive roles
- Cloud Storage: bucket permissions, public access, encryption
- GCE: firewall rules, OS Login, serial port access
- GKE: security posture, workload identity, network policies
- Cloud Audit Logs: admin activity, data access
- Security Command Center: findings y threats
- VPC: firewall rules abiertas, VPC Flow Logs
- BigQuery: public datasets, authorized views
- Cloud Functions: permissions, environment variables

Responde en JSON: risk_score, project, service_findings, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del proyecto GCP:

PROYECTO: {data.get('project_id', 'unknown')}

RECURSOS GCP:
{json.dumps(data.get('resources', {}), indent=2, default=str)[:3000]}

SCC FINDINGS:
{json.dumps(data.get('scc_findings', [])[:15], indent=2, default=str)[:1000]}

Detecta riesgos críticos en Google Cloud."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "service_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo GCP"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.83),
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
