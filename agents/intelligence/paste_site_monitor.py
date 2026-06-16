"""Agente Monitor de Paste Sites."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class PasteSiteMonitorAgent(BaseAgent):
    name = "PasteSiteMonitorAgent"
    description = "Monitoreo de Pastebin, GitHub Gists y similares — credenciales, datos sensibles"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.MEDIUM
    tags = ["pastebin", "github", "gist", "data-leak", "credentials"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Paste Sites del AI-SOC. Detectas en Pastebin, GitHub Gists, etc.:
- Credenciales corporativas publicadas accidentalmente
- Connection strings con passwords
- API keys y tokens de servicios
- PII de empleados o clientes
- Código fuente propietario
- Datos internos de la organización
- IOCs y notas de atacantes sobre el objetivo

Responde en JSON: risk_score, leak_type, sensitive_data_found, source_url, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las siguientes publicaciones en paste sites:

ORGANIZACIÓN: {data.get('organization', 'unknown')}
DOMINIO: {data.get('domain', 'unknown')}

PASTES ENCONTRADOS:
{json.dumps(data.get('pastes', [])[:10], indent=2, default=str)[:3000]}

KEYWORDS MONITOREADAS: {data.get('keywords', [])}

Determina si hay datos sensibles expuestos y las acciones a tomar."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "sensitive_data_found": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Datos Sensibles en Paste Site"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.DATA_EXFILTRATION,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("sensitive_data_found", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
