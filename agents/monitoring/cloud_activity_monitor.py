"""Agente Monitor de Actividad Cloud."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class CloudActivityMonitorAgent(BaseAgent):
    name = "CloudActivityMonitorAgent"
    description = "Monitoreo de actividad cloud multi-proveedor — eventos, IAM, API calls"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["cloud", "aws", "azure", "gcp", "activity", "cloudtrail"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Actividad Cloud del AI-SOC. Analizas eventos cloud para detectar:
- Accesos no autorizados a recursos cloud
- Escalada de privilegios IAM
- Exfiltración de datos desde servicios cloud
- Creación de recursos no autorizados (crypto mining)
- Configuraciones incorrectas expuestas
- Acceso desde ubicaciones geográficas inusuales
- Actividad fuera del horario normal

Responde en JSON: risk_score, cloud_stats, anomalies, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la siguiente actividad cloud:

PROVEEDOR: {data.get('provider', 'AWS')}
CUENTA/SUSCRIPCIÓN: {data.get('account', 'unknown')}
REGIÓN: {data.get('region', 'unknown')}

EVENTOS API:
{json.dumps(data.get('api_calls', [])[:100], indent=2, default=str)[:4000]}

ALERTAS NATIVAS: {data.get('native_alerts', [])}
USUARIO/ROL: {data.get('identity', 'unknown')}

Detecta comportamiento malicioso y uso indebido de recursos cloud."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "anomalies": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Actividad Sospechosa en Cloud"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.75),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("anomalies", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
