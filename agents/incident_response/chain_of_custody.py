"""Agente de Cadena de Custodia."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity


class ChainOfCustodyAgent(BaseAgent):
    name = "ChainOfCustodyAgent"
    description = "Gestión de cadena de custodia forense — documentación legal, transferencias, integridad"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.MEDIUM
    tags = ["chain-of-custody", "legal", "forensics", "documentation", "compliance"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Cadena de Custodia del AI-SOC. Mantienes la integridad legal de evidencias:
- Registro de quién accedió a qué evidencia y cuándo
- Transferencias de evidencias con firma
- Verificación de hashes en cada transferencia
- Almacenamiento seguro y acceso controlado
- Generación de formularios de cadena de custodia
- Preparación para presentación en tribunales

Responde en JSON: custody_record, evidence_status, integrity_check, alerts, documentation."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Gestiona la cadena de custodia:

INCIDENTE: {data.get('incident_id', 'unknown')}
EVIDENCIAS: {json.dumps(data.get('evidence_list', [])[:20], indent=2, default=str)[:1500]}
TRANSFERENCIAS: {json.dumps(data.get('transfers', [])[:10], indent=2, default=str)[:500]}
HASH ORIGINAL: {data.get('original_hashes', {})}
HASH ACTUAL: {data.get('current_hashes', {})}

Verifica la integridad y genera el registro de custodia."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"custody_record": {}, "integrity_check": {}, "alerts": [], "documentation": ""})

        alerts = [
            self._create_alert(
                title="Falla de Integridad en Evidencia",
                description="Los hashes no coinciden — evidencia posiblemente comprometida",
                severity=Severity.CRITICAL,
                confidence=0.95,
            )
        ] if not result.get("integrity_check", {}).get("passed", True) else []

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[result.get("custody_record", {})],
            alerts=alerts,
            iocs=[],
            risk_score=0.0 if result.get("integrity_check", {}).get("passed", True) else 9.0,
            confidence=0.97,
            recommendations=[result.get("documentation", "")],
            raw_ai_response=response,
        )
