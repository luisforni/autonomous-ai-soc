"""Agente AWS GuardDuty."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class AWSGuardDutyAgent(BaseCloudAgent):
    name = "AWSGuardDutyAgent"
    description = "Integración con AWS GuardDuty — análisis y enriquecimiento de findings"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "AWS"
    tags = ["aws", "guardduty", "threat-detection", "cloud"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente AWS GuardDuty del AI-SOC. Enriqueces y priorizas los findings de GuardDuty:
- Correlacionas findings relacionados para construir el contexto del ataque
- Priorizas por severidad real y blast radius
- Identificas falsos positivos
- Propones acciones de respuesta inmediata
- Mapeas con MITRE ATT&CK

Responde en JSON: risk_score, finding_summary, correlated_findings, alerts, response_actions, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza y enriquece los findings de GuardDuty:

CUENTA: {data.get('account_id', 'unknown')}
DETECTOR ID: {data.get('detector_id', 'unknown')}

FINDINGS:
{json.dumps(data.get('findings', [])[:30], indent=2, default=str)[:4000]}

Correlaciona los findings y determina el nivel real de riesgo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "correlated_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "GuardDuty Finding"),
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
            findings=result.get("correlated_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("response_actions", result.get("recommendations", [])),
            raw_ai_response=response,
        )
