"""Agente Recolector de Evidencias Forenses."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ForensicsCollectorAgent(BaseAgent):
    name = "ForensicsCollectorAgent"
    description = "Recolección de evidencias forenses — triage remoto, preservación, cadena de custodia"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.HIGH
    tags = ["forensics", "evidence", "collection", "triage", "incident"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente Recolector de Evidencias Forenses del AI-SOC. Coordinas la recolección:

Evidencias a recolectar (por orden de volatilidad):
1. Memoria RAM (más volátil)
2. Procesos activos, conexiones de red, usuarios
3. Logs del sistema (syslog, event log)
4. Filesystem: artefactos recientes, modified files
5. Registro de Windows
6. Disco completo (imagen forense)

Principios forenses:
- Preservar la evidencia sin alterarla
- Calcular hashes antes/después
- Documentar la cadena de custodia
- Orden de volatilidad

Responde en JSON: risk_score, collection_plan, volatile_artifacts, persistent_artifacts, collection_commands, chain_of_custody_template, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera plan de recolección de evidencias:

SISTEMA: {data.get('hostname', 'unknown')} | OS: {data.get('os', 'unknown')}
INCIDENTE: {data.get('incident_id', 'unknown')}
TIPO DE INCIDENTE: {data.get('incident_type', 'unknown')}

EVIDENCIAS YA RECOLECTADAS: {data.get('collected_evidence', [])}
ACCESO DISPONIBLE: {data.get('access_level', 'remote')}
TIEMPO DISPONIBLE: {data.get('time_available', '2 horas')}

Genera los comandos específicos para recolectar evidencias preservando la integridad forense."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "collection_plan": {}, "volatile_artifacts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Recolección Forense Requerida"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[x for f in ("volatile_artifacts", "persistent_artifacts") for x in (result.get(f) if isinstance(result.get(f), list) else [])],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("collection_commands", []),
            raw_ai_response=response,
        )
