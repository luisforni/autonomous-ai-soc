"""Agente Enriquecedor de IOCs."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity


class IOCEnricherAgent(BaseAgent):
    name = "IOCEnricherAgent"
    description = "Enriquecimiento automático de IOCs — reputación, contexto, relaciones, TTPs"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.HIGH
    tags = ["ioc", "enrichment", "virustotal", "shodan", "reputation"]

    def _build_system_prompt(self) -> str:
        return """Eres el Enriquecedor de IOCs del AI-SOC. Para cada IOC (IP, dominio, hash, URL, email):

Enrichment aplicado:
- IPs: ASN, país, abuse score, puertos abiertos (Shodan), historial de actividad maliciosa
- Dominios: WHOIS, edad del dominio, historial DNS, categoría (hosting, VPN, TOR)
- Hashes: detecciones en AV, familia de malware, primera/última vez visto
- URLs: categoría, redirecciones, contenido malicioso
- Emails: dominio del remitente, brechas de datos asociadas

Contexto adicional:
- ¿Es infraestructura de actores conocidos?
- ¿Está en listas negras?
- ¿Tiene falsos positivos conocidos?
- Score de confianza ajustado

Responde en JSON: risk_score, enriched_iocs, correlations, alerts, summary."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Enriquece los siguientes IOCs:

IOCs A ENRIQUECER:
{json.dumps(data.get('iocs', [])[:20], indent=2, default=str)[:2000]}

CONTEXTO DEL INCIDENTE: {data.get('incident_context', 'análisis de amenaza')}
CLIENTE: {data.get('client_sector', 'desconocido')}

Proporciona contexto completo para cada IOC y ajusta el score de riesgo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "enriched_iocs": [], "alerts": [], "summary": ""})

        alerts = []
        for enriched in result.get("enriched_iocs", []):
            if enriched.get("malicious_score", 0) >= 0.8:
                alerts.append(self._create_alert(
                    title=f"IOC Malicioso Confirmado: {enriched.get('value', '')}",
                    description=enriched.get("context", ""),
                    severity=Severity.HIGH,
                    confidence=float(enriched.get("malicious_score", 0.8)),
                ))

        iocs = []
        for ioc_data in result.get("enriched_iocs", []):
            try:
                ioc = IOC(
                    type=IOCType(ioc_data.get("type", "ip")),
                    value=ioc_data.get("value", ""),
                    confidence=float(ioc_data.get("malicious_score", 0.5)),
                    source=self.name,
                    enrichment=ioc_data.get("enrichment_data", {}),
                    tags=ioc_data.get("tags", []),
                )
                iocs.append(ioc)
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("correlations", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=[result.get("summary", "")],
            raw_ai_response=response,
        )
