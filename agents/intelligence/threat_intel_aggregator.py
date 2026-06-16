"""Agente Agregador de Inteligencia de Amenazas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class ThreatIntelAggregatorAgent(BaseAgent):
    name = "ThreatIntelAggregatorAgent"
    description = "Agregación y correlación de inteligencia de amenazas — MISP, OTX, STIX/TAXII"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.HIGH
    tags = ["threat-intel", "misp", "otx", "stix", "taxii", "feeds"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agregador de Inteligencia de Amenazas del AI-SOC. Procesas y correlacionas inteligencia de:

Fuentes:
- MISP: plataforma de compartición de IOCs
- AlienVault OTX: Open Threat Exchange
- VirusTotal: reputación de archivos, URLs, IPs
- STIX/TAXII feeds: formatos estándar de CTI
- ISACs sectoriales (FS-ISAC, H-ISAC)
- CISA Known Exploited Vulnerabilities (KEV)
- Threat feeds comerciales

Procesas:
- Deduplicación y normalización de IOCs
- Puntuación de confianza por fuente
- Correlación entre campañas
- Relevancia por sector del cliente
- Aging de indicadores (TTL)

Responde en JSON: risk_score, active_campaigns, new_iocs, relevant_threats, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Agrega y analiza la inteligencia de amenazas:

SECTOR DEL CLIENTE: {data.get('sector', 'fintech')}
PAÍS: {data.get('country', 'Argentina')}

FEEDS RECIENTES:
{json.dumps(data.get('feeds', [])[:20], indent=2, default=str)[:3000]}

IOCs NUEVOS:
{json.dumps(data.get('new_iocs', [])[:30], indent=2, default=str)[:2000]}

CAMPAÑAS ACTIVAS CONOCIDAS: {data.get('known_campaigns', [])}

Identifica las amenazas más relevantes para el cliente y genera alertas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "active_campaigns": [], "new_iocs": [], "alerts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza Relevante Detectada"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.8),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("new_iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name, confidence=ioc_data.get("confidence", 0.7)))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("active_campaigns", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.8,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
