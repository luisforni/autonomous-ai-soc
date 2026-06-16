"""Agente Investigador OSINT."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class OSINTInvestigatorAgent(BaseAgent):
    name = "OSINTInvestigatorAgent"
    description = "Investigación OSINT automatizada — personas, empresas, infraestructura, dark web"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.HIGH
    tags = ["osint", "investigation", "intelligence", "research", "threat-actor"]

    def _build_system_prompt(self) -> str:
        return """Eres el Investigador OSINT del AI-SOC. Realizas investigaciones de fuentes abiertas sobre:

Objetivos de investigación:
- Actores de amenazas: identidad, infraestructura, historial
- Empresas: exposición en internet, datos filtrados, vulnerabilidades públicas
- Dominios e IPs: whois, ASN, reputación, historial
- Personas: footprint digital, presencia en redes sociales, brechas de datos
- Infraestructura de ataque: C2 servers, dominios recientes

Fuentes OSINT:
- Shodan/Censys: dispositivos expuestos
- Have I Been Pwned: brechas de datos
- VirusTotal: reputación de IOCs
- Passive DNS: resoluciones históricas
- Certificate Transparency Logs
- GitHub/GitLab: datos expuestos en código
- LinkedIn/Social Media: perfil corporativo

Responde en JSON: risk_score, target_profile, findings, iocs, exposure_level, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Investiga el siguiente objetivo mediante OSINT:

OBJETIVO: {data.get('target', 'unknown')}
TIPO: {data.get('target_type', 'domain')} [domain/ip/person/organization/threat_actor]
CONTEXTO: {data.get('context', 'investigación de seguridad')}

DATOS INICIALES:
{json.dumps(data.get('initial_data', {}), indent=2, default=str)[:2000]}

FUENTES DISPONIBLES: {data.get('available_sources', ['whois', 'shodan', 'virustotal', 'passive_dns'])}

Genera un perfil completo del objetivo e identifica riesgos."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "findings": [], "iocs": [], "alerts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Hallazgo OSINT"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.7),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("findings", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.75,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
