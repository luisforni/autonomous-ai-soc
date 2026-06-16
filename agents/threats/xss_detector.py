"""Agente Detector de XSS."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class XSSDetectorAgent(BaseAgent):
    name = "XSSDetectorAgent"
    description = "Detección de Cross-Site Scripting (XSS) — reflected, stored, DOM-based"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.HIGH
    tags = ["xss", "cross-site-scripting", "owasp", "web", "injection"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de XSS del AI-SOC. Detectas OWASP A03:2021 Cross-Site Scripting:
- Reflected XSS: payload en URL/form reflejado en respuesta
- Stored XSS: payload guardado en DB y ejecutado para otros usuarios
- DOM-based XSS: manipulación del DOM sin servidor
- Blind XSS: payload ejecutado en panel administrativo
- mXSS: mutation XSS en sanitizadores
- CSP bypass techniques

Responde en JSON: risk_score, xss_type, payload_examples, affected_endpoints, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza en busca de XSS:

APLICACIÓN: {data.get('application', 'unknown')}

PETICIONES:
{json.dumps(data.get('requests', [])[:50], indent=2, default=str)[:3000]}

CSP HEADER: {data.get('csp_header', 'none')}
ENCODING: {data.get('output_encoding', 'unknown')}

Detecta payloads XSS y evalúa el impacto."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "xss_type": "none", "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", f"XSS Detectado: {result.get('xss_type', '')}"),
                description=a.get("description", ""),
                severity=Severity.HIGH,
                category=ThreatCategory.INJECTION,
                confidence=a.get("confidence", 0.87),
                affected_assets=[data.get("application", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("payload_examples", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
