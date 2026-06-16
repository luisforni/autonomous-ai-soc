"""Agente de Inteligencia de Dominios."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class DomainIntelligenceAgent(BaseAgent):
    name = "DomainIntelligenceAgent"
    description = "Inteligencia de dominios — WHOIS, DNS, historial, reputación, infraestructura"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.MEDIUM
    tags = ["domain", "dns", "whois", "passive-dns", "reputation"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Inteligencia de Dominios del AI-SOC. Analizas dominios:
- WHOIS: registrante, registrar, fechas, privacidad
- Historial DNS: cambios de IP, MX records, SPF/DKIM
- Passive DNS: dominios relacionados en la misma IP
- Certificados SSL: Common Name, SANs, issuer
- Edad del dominio (dominios muy nuevos = alta sospecha)
- Registrar: registradores usados por threat actors
- Hosting en bulletproof providers
- Categoría: hosting, VPN, TOR exit, proxy, spam

Responde en JSON: risk_score, domain_info, risk_factors, related_domains, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la inteligencia del dominio:

DOMINIO: {data.get('domain', 'unknown')}

DATOS DNS:
{json.dumps(data.get('dns_data', {}), indent=2, default=str)[:1500]}

WHOIS:
{json.dumps(data.get('whois', {}), indent=2, default=str)[:1000]}

HISTORIAL PASIVO:
{json.dumps(data.get('passive_dns', [])[:15], indent=2, default=str)[:1000]}

CERTIFICADOS: {data.get('certificates', [])}

Evalúa el riesgo del dominio y relaciona con infraestructura maliciosa conocida."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "domain_info": {}, "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Dominio Sospechoso"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.75),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for domain in result.get("related_domains", []):
            if domain:
                iocs.append(IOC(type=IOCType.DOMAIN, value=str(domain), confidence=0.7, source=self.name))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("risk_factors", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.78,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
