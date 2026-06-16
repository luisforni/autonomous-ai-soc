"""Agente de Protección de Marca."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class BrandProtectionAgent(BaseAgent):
    name = "BrandProtectionAgent"
    description = "Protección de marca digital — typosquatting, phishing de marca, impersonación"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.MEDIUM
    tags = ["brand", "typosquatting", "phishing", "impersonation", "trademark"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Protección de Marca del AI-SOC. Detectas:
- Dominios typosquatting (banc0.com vs banco.com)
- Sitios de phishing usando logos e identidad de la marca
- Aplicaciones móviles falsas en app stores
- Cuentas de redes sociales impostoras
- Uso no autorizado de marca en campañas de spam
- Subdominios maliciosos bajo dominios oficiales

Responde en JSON: risk_score, domain_findings, social_media_findings, app_findings, alerts, iocs, takedown_recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la protección de marca para:

MARCA: {data.get('brand_name', 'unknown')}
DOMINIO OFICIAL: {data.get('official_domain', 'unknown')}
SECTOR: {data.get('sector', 'unknown')}

DOMINIOS SOSPECHOSOS:
{json.dumps(data.get('suspicious_domains', [])[:30], indent=2, default=str)[:2000]}

REDES SOCIALES IMPERSONANDO: {data.get('fake_social_accounts', [])}
APPS FALSAS: {data.get('fake_apps', [])}

Identifica las amenazas más urgentes y propone acciones de takedown."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "domain_findings": [], "iocs": [], "takedown_recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza a la Marca"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.PHISHING,
                confidence=a.get("confidence", 0.82),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for domain in result.get("domain_findings", []):
            if isinstance(domain, dict) and domain.get("domain"):
                iocs.append(IOC(type=IOCType.DOMAIN, value=domain["domain"], confidence=0.8, source=self.name, tags=["typosquatting"]))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("domain_findings", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("takedown_recommendations", []),
            raw_ai_response=response,
        )
