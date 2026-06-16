"""Agente Azure Sentinel."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class AzureSentinelAgent(BaseCloudAgent):
    name = "AzureSentinelAgent"
    description = "Integración con Microsoft Sentinel — análisis de incidentes y alertas"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "Azure"
    tags = ["azure", "sentinel", "siem", "microsoft", "incidents"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente Azure Sentinel del AI-SOC. Procesas incidentes y alertas de Microsoft Sentinel:
- Análisis de incidentes con múltiples alerts correlacionadas
- Enriquecimiento con threat intelligence integrada
- Investigación de entidades (usuarios, IPs, hosts)
- Bookmarks de evidencias relevantes
- Hunting queries basadas en los hallazgos
- Automatización de respuesta (Playbooks)

Responde en JSON: risk_score, incident_analysis, entities, hunting_queries, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el incidente de Azure Sentinel:

WORKSPACE: {data.get('workspace_id', 'unknown')}
INCIDENTE: {data.get('incident_id', 'unknown')}
TÍTULO: {data.get('title', 'unknown')}
SEVERIDAD: {data.get('severity', 'unknown')}

ALERTAS RELACIONADAS:
{json.dumps(data.get('alerts', [])[:20], indent=2, default=str)[:2000]}

ENTIDADES:
{json.dumps(data.get('entities', [])[:20], indent=2, default=str)[:1000]}

EVIDENCIAS: {data.get('evidence', [])}

Analiza el incidente y propone acciones de respuesta."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "incident_analysis": {}, "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Incidente Sentinel"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[result.get("incident_analysis", {})],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
