"""Agente de Análisis Geoespacial."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class GeolocationAnalyzerAgent(BaseAgent):
    name = "GeolocationAnalyzerAgent"
    description = "Análisis geoespacial de amenazas — origen de ataques, impossible travel, geofencing"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.MEDIUM
    tags = ["geolocation", "geography", "impossible-travel", "geofencing", "country-risk"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador Geoespacial del AI-SOC. Detectas anomalías geográficas:
- Impossible travel: login desde España y luego en 2 minutos desde China
- Accesos desde países sancionados (OFAC: Rusia, Irán, RPDC, etc.)
- Accesos desde TOR exit nodes o VPNs conocidos
- Correlación geográfica de atacantes con APTs conocidos
- Geofencing violations: acceso desde fuera del país del cliente

Responde en JSON: risk_score, geo_anomalies, origin_countries, impossible_travel_cases, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las anomalías geográficas:

USUARIO/ENTIDAD: {data.get('entity', 'unknown')}
PAÍS BASE: {data.get('base_country', 'unknown')}
PAÍSES PERMITIDOS: {data.get('allowed_countries', [])}

ACCESOS POR UBICACIÓN:
{json.dumps(data.get('access_locations', [])[:30], indent=2, default=str)[:2000]}

Detecta impossible travel y accesos desde países de alto riesgo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "geo_anomalies": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Anomalía Geográfica Detectada"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.ANOMALY,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("geo_anomalies", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
