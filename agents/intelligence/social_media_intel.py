"""Agente de Inteligencia en Redes Sociales."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class SocialMediaIntelAgent(BaseAgent):
    name = "SocialMediaIntelAgent"
    description = "Inteligencia en redes sociales — menciones, campañas de desinformación, actores"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.LOW
    tags = ["social-media", "twitter", "linkedin", "intelligence", "disinformation"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Inteligencia en Redes Sociales del AI-SOC. Analizas:
- Menciones de la organización en redes sociales
- Campañas de desinformación coordinadas
- Cuentas de atacantes que publican sobre el objetivo
- Anuncios de ataques antes de ejecutarse
- Reconocimiento público de la infraestructura
- Hacktivistas organizándose contra el objetivo
- Filtración de información interna vía empleados

Responde en JSON: risk_score, threat_type, relevant_posts, actor_accounts, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la inteligencia en redes sociales:

ORGANIZACIÓN: {data.get('organization', 'unknown')}

POSTS RELEVANTES:
{json.dumps(data.get('posts', [])[:20], indent=2, default=str)[:2000]}

CUENTAS SOSPECHOSAS:
{json.dumps(data.get('suspicious_accounts', [])[:10], indent=2, default=str)[:500]}

PERIODO: {data.get('time_window', 'últimas 24h')}

Identifica amenazas reales vs ruido."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "relevant_posts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza en Redes Sociales"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.SOCIAL_ENGINEERING,
                confidence=a.get("confidence", 0.68),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("relevant_posts", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.68,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
