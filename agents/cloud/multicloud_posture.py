"""Agente Multi-Cloud Posture (CSPM)."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class MultiCloudPostureAgent(BaseCloudAgent):
    name = "MultiCloudPostureAgent"
    description = "Gestión de postura de seguridad multi-cloud (CSPM) — AWS + Azure + GCP"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "multi-cloud"
    tags = ["cspm", "posture", "multi-cloud", "compliance", "benchmark"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente CSPM Multi-cloud del AI-SOC. Gestionas la postura de seguridad en entornos multi-cloud:
- CIS Benchmarks para AWS, Azure y GCP
- NIST CSF, ISO 27001, SOC 2 controles cloud
- Puntuación consolidada de seguridad
- Drift de configuración vs baseline
- Remediación automática vs manual
- Priorización por riesgo real (explotabilidad + exposición)
- Tendencias y evolución del riesgo

Responde en JSON: risk_score, overall_posture_score, cloud_scores, top_risks, alerts, remediation_plan."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Evalúa la postura de seguridad multi-cloud:

AMBIENTES:
{json.dumps(data.get('environments', {}), indent=2, default=str)[:4000]}

BENCHMARK RESULTS:
{json.dumps(data.get('benchmark_results', {}), default=str)[:1000]}

HISTÓRICO DE POSTURA: {data.get('posture_history', [])}

Genera el reporte consolidado de postura y plan de remediación priorizado."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "top_risks": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo de Postura Cloud"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("top_risks", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("remediation_plan", result.get("recommendations", [])),
            raw_ai_response=response,
        )
