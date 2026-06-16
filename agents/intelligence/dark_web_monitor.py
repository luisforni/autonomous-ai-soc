"""Agente Monitor de Dark Web."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class DarkWebMonitorAgent(BaseAgent):
    name = "DarkWebMonitorAgent"
    description = "Monitoreo de dark web — credenciales filtradas, venta de accesos, datos robados"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.HIGH
    tags = ["dark-web", "tor", "credentials", "data-breach", "ransomware-leak"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Dark Web del AI-SOC. Analizas hallazgos de dark web relevantes para el cliente:

Monitoreas:
- Credenciales corporativas en foros de hacking (combo lists)
- Venta de acceso inicial a la organización (Initial Access Brokers)
- Datos corporativos en sitios de leak de ransomware
- Información de tarjetas de crédito / datos financieros
- PII de empleados o clientes en brechas
- Conversaciones sobre la organización en foros
- Contratos, documentos confidenciales expuestos

Fuentes monitoreadas:
- Foros: BreachForums, RaidForums (histórico), XSS.is
- Ransomware leak sites: LockBit, BlackCat, Cl0p blogs
- Paste sites: Pastebin, Doxbin
- TOR hidden services

Responde en JSON: risk_score, findings, leaked_data_types, threat_actors_involved, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza los hallazgos de dark web para el cliente:

ORGANIZACIÓN: {data.get('organization', 'unknown')}
DOMINIO: {data.get('domain', 'unknown')}
SECTOR: {data.get('sector', 'unknown')}

HALLAZGOS:
{json.dumps(data.get('findings', [])[:20], indent=2, default=str)[:3000]}

MENCIONES DETECTADAS: {data.get('mentions', [])}
CREDENCIALES ENCONTRADAS: {data.get('credential_count', 0)}
ÚLTIMA BÚSQUEDA: {data.get('last_search', 'unknown')}

Evalúa el impacto y determina acciones inmediatas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "findings": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Datos Encontrados en Dark Web"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "critical")),
                category=ThreatCategory.DATA_EXFILTRATION,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
