"""Agente GCP Cloud Armor."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class GCPCloudArmorAgent(BaseCloudAgent):
    name = "GCPCloudArmorAgent"
    description = "Análisis de GCP Cloud Armor — WAF rules, DDoS protection, security policies"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.MEDIUM
    provider = "GCP"
    tags = ["gcp", "cloud-armor", "waf", "ddos", "security-policy"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador GCP Cloud Armor del AI-SOC. Analizas la protección web en GCP:
- Security policies y reglas WAF
- Ataques bloqueados y permitidos
- Rate limiting efectividad
- Reglas OWASP aplicadas
- Bot management
- Adaptive protection activación

Responde en JSON: risk_score, armor_summary, blocked_attacks, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza Cloud Armor:

PROYECTO: {data.get('project_id', 'unknown')}
POLÍTICA: {data.get('security_policy', 'unknown')}

EVENTOS:
{json.dumps(data.get('events', [])[:50], indent=2, default=str)[:3000]}

Detecta ataques y evalúa la efectividad de las reglas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "blocked_attacks": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Ataque Detectado por Cloud Armor"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.DDOS,
                confidence=a.get("confidence", 0.8),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("blocked_attacks", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
