"""Agente Perfilador de Actores de Amenazas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ThreatActorProfilerAgent(BaseAgent):
    name = "ThreatActorProfilerAgent"
    description = "Perfilado de actores de amenazas — grupos APT, ransomware gangs, motivaciones"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.HIGH
    tags = ["threat-actor", "apt", "profiling", "attribution", "ransomware-group"]

    def _build_system_prompt(self) -> str:
        return """Eres el Perfilador de Actores de Amenazas del AI-SOC. Generas perfiles detallados de:

Información del perfil:
- Nombre y aliases del grupo
- Origen/afiliación geográfica/estatal
- Motivación: espionaje, financiero, perturbación, hacktivismo
- Sectores objetivo preferidos
- TTPs característicos (MITRE ATT&CK)
- Herramientas y malware asociados
- Historial de campañas conocidas
- Infraestructura (ASNs, ranges de IP, dominios)
- Nivel de sofisticación técnica

Responde en JSON: actor_profile, threat_level, targeted_sectors, current_campaigns, iocs, alerts, defensive_recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera el perfil del actor de amenazas:

ACTOR: {data.get('actor_name', 'unknown')}
EVIDENCIAS:
{json.dumps(data.get('evidence', [])[:20], indent=2, default=str)[:2000]}

IOCs ATRIBUIDOS:
{json.dumps(data.get('iocs', [])[:15], indent=2, default=str)[:1000]}

TTPs OBSERVADOS: {data.get('ttps', [])}
OBJETIVOS CONOCIDOS: {data.get('known_targets', [])}

Genera el perfil completo y evalúa el riesgo para nuestros clientes."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"actor_profile": {}, "alerts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Actor de Amenaza Identificado"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.APT,
                confidence=a.get("confidence", 0.75),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[result.get("actor_profile", {})],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("threat_level"), 5),
            confidence=0.75,
            recommendations=result.get("defensive_recommendations", []),
            raw_ai_response=response,
        )
