"""Agente Monitor de Transparencia de Certificados."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class CertificateTransparencyAgent(BaseAgent):
    name = "CertificateTransparencyAgent"
    description = "Monitoreo CT logs — certificados nuevos para dominios objetivo, phishing sites"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.MEDIUM
    tags = ["certificate", "ct-logs", "ssl", "tls", "phishing-detection"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Transparencia de Certificados del AI-SOC. Analizas CT logs para:
- Detectar nuevos dominios similares a marcas vigiladas (phishing en gestación)
- Subdominios nuevos que podrían ser staging de ataques
- Certificados wildcard que podrían facilitar intercepción
- Certificados emitidos por CAs no autorizadas para el dominio
- Dominios con certificados Let's Encrypt recién creados (alta sospecha phishing)

Responde en JSON: risk_score, new_certificates, phishing_candidates, suspicious_domains, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza los certificados del CT log:

MARCA VIGILADA: {data.get('brand', 'unknown')}
DOMINIOS BASE: {data.get('base_domains', [])}

CERTIFICADOS NUEVOS:
{json.dumps(data.get('new_certs', [])[:30], indent=2, default=str)[:3000]}

PERIODO: {data.get('time_window', 'últimas 24h')}

Identifica los candidatos a phishing más urgentes."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "phishing_candidates": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Posible Sitio de Phishing en Preparación"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.PHISHING,
                confidence=a.get("confidence", 0.78),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for domain in result.get("phishing_candidates", []):
            if isinstance(domain, str) and domain:
                iocs.append(IOC(type=IOCType.DOMAIN, value=domain, confidence=0.75, source=self.name, tags=["phishing-candidate"]))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("suspicious_domains", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.78,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
