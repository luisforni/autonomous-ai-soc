"""Agente Detector de Phishing."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class PhishingDetectorAgent(BaseAgent):
    name = "PhishingDetectorAgent"
    description = "Detección de phishing, spear-phishing y BEC con análisis de IA"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["phishing", "bec", "spear-phishing", "email", "urls"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Phishing del AI-SOC — experto en ataques de ingeniería social.

Detectas:
1. Phishing genérico: plantillas comunes, logos falsos, urgencia artificial
2. Spear-phishing: personalización, contexto específico del objetivo
3. BEC (Business Email Compromise): impersonación de ejecutivos, fraude de transferencias
4. Smishing: SMS phishing
5. Vishing: voice phishing indicators
6. Clone phishing: réplicas de emails legítimos

Analizas:
- Dominio del remitente vs dominio legítimo (lookalike domains)
- URLs acortadas o con redirecciones
- Formularios de captura de credenciales
- Adjuntos maliciosos (macros, EXEs disfrazados)
- Lenguaje: urgencia, amenaza, recompensa
- SPF/DKIM/DMARC failures
- Metadata del email

Responde en JSON: risk_score, phishing_type, confidence, indicators, targeted_users, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el siguiente email/contenido en busca de phishing:

REMITENTE: {data.get('from', '')}
DOMINIO REMITENTE: {data.get('from_domain', '')}
ASUNTO: {data.get('subject', '')}
DESTINATARIO: {data.get('to', '')}

CABECERAS:
Return-Path: {data.get('return_path', '')}
Reply-To: {data.get('reply_to', '')}
X-Originating-IP: {data.get('originating_ip', '')}

AUTENTICACIÓN:
SPF: {data.get('spf', 'unknown')} | DKIM: {data.get('dkim', 'unknown')} | DMARC: {data.get('dmarc', 'unknown')}

CUERPO DEL EMAIL:
{str(data.get('body', ''))[:2000]}

URLS ENCONTRADAS:
{json.dumps(data.get('urls', [])[:20], indent=2, default=str)}

ADJUNTOS: {data.get('attachments', [])}

Determina si es phishing, el tipo y nivel de sofisticación."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "phishing_type": "none", "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        if self._parse_score(result.get("risk_score")) >= 5:
            alerts.append(self._create_alert(
                title=f"Phishing Detectado: {result.get('phishing_type', 'Genérico')}",
                description=f"Email phishing de {data.get('from', 'unknown')} hacia {data.get('to', 'unknown')}",
                severity=Severity.HIGH if self._parse_score(result.get("risk_score")) >= 7 else Severity.MEDIUM,
                category=ThreatCategory.PHISHING,
                confidence=self._parse_score(result.get("confidence"), 0.8),
                recommendations=result.get("recommendations", []),
            ))

        iocs = []
        for url in data.get("urls", []):
            if isinstance(url, str) and url:
                iocs.append(IOC(type=IOCType.URL, value=url, confidence=0.7, source=self.name))

        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("indicators", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=self._parse_score(result.get("confidence"), 0.8),
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
