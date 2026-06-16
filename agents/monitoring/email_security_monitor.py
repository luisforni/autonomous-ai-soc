"""Agente Monitor de Seguridad de Email — phishing, BEC, malware adjunto."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class EmailSecurityMonitorAgent(BaseAgent):
    name = "EmailSecurityMonitorAgent"
    description = "Monitoreo de seguridad de correo: phishing, BEC, malware adjunto, spoofing"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["email", "phishing", "bec", "spam", "malware"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Seguridad de Email del AI-SOC. Analizas correos electrónicos para detectar:
- Phishing y spear-phishing
- Business Email Compromise (BEC)
- Malware en adjuntos (macros maliciosas, ejecutables disfrazados)
- Spoofing de dominio y SPF/DKIM/DMARC failures
- Credential harvesting
- Urgencia artificial y manipulación social
- URLs maliciosas embebidas

Responde en JSON: risk_score, email_stats, phishing_indicators, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el siguiente email para detectar amenazas:

CABECERAS:
{json.dumps(data.get('headers', {}), indent=2, default=str)}

ASUNTO: {data.get('subject', '')}
REMITENTE: {data.get('from', '')}
DESTINATARIOS: {data.get('to', [])}
CUERPO:
{str(data.get('body', ''))[:2000]}

ADJUNTOS: {data.get('attachments', [])}
URLS ENCONTRADAS: {data.get('urls', [])}
SPF: {data.get('spf_result', 'unknown')}
DKIM: {data.get('dkim_result', 'unknown')}
DMARC: {data.get('dmarc_result', 'unknown')}"""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza en Email"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.PHISHING,
                confidence=a.get("confidence", 0.8),
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
            findings=result.get("phishing_indicators", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
