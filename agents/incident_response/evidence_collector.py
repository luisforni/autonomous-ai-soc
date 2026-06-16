"""Agente Recolector de Evidencias."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class EvidenceCollectorAgent(BaseAgent):
    name = "EvidenceCollectorAgent"
    description = "Recolección y preservación de evidencias digitales para procesos legales"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.HIGH
    tags = ["evidence", "legal", "preservation", "hash", "documentation"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Recolección de Evidencias del AI-SOC. Preservas evidencias para uso legal:
- Generación de hashes (MD5, SHA1, SHA256) de todas las evidencias
- Documentación de la cadena de custodia
- Captura de pantalla firmada digitalmente
- Log de acciones tomadas durante la respuesta
- Empaquetado forense (zip con contraseña, cifrado)
- Inventario de evidencias
- Exportación en formatos aceptados por tribunales

Responde en JSON: risk_score, evidence_inventory, hash_values, custody_log, preservation_status, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Recolecta y preserva las evidencias:

INCIDENTE: {data.get('incident_id', 'unknown')}
POSIBLE ACCIÓN LEGAL: {data.get('legal_action', False)}

EVIDENCIAS DISPONIBLES:
{json.dumps(data.get('available_evidence', [])[:20], indent=2, default=str)[:2000]}

HASHES CALCULADOS:
{json.dumps(data.get('hashes', {}), indent=2, default=str)[:1000]}

PERSONAL INVOLUCRADO: {data.get('responders', [])}

Genera el inventario forense completo con cadena de custodia."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "evidence_inventory": [], "custody_log": [], "recommendations": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("evidence_inventory", []),
            alerts=[],
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.95,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
