"""Agente Analizador Cloud Genérico Multi-cloud."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class CloudAnalyzerAgent(BaseCloudAgent):
    name = "CloudAnalyzerAgent"
    description = "Análisis de seguridad cloud genérico multi-proveedor (AWS, Azure, GCP)"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "multi-cloud"
    tags = ["cloud", "multi-cloud", "cspm", "security", "posture"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador Cloud Multi-proveedor del AI-SOC. Detectas amenazas y misconfiguraciones en cualquier entorno cloud:
- Recursos expuestos públicamente sin necesidad
- Políticas IAM excesivamente permisivas
- Cifrado no habilitado en datos en reposo/tránsito
- Grupos de seguridad/NSGs con acceso abierto
- Logging y monitoreo insuficiente
- Recursos sin autenticación MFA
- Buckets/Blobs de almacenamiento públicos
- Instancias con vulnerabilidades conocidas

Responde en JSON: risk_score, provider, cloud_findings, misconfigurations, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la postura de seguridad cloud:

PROVEEDOR: {data.get('provider', 'AWS')}
CUENTA: {data.get('account', 'unknown')}
REGIÓN: {data.get('region', 'all')}

RECURSOS:
{json.dumps(data.get('resources', [])[:30], indent=2, default=str)[:2000]}

CONFIGURACIONES:
{json.dumps(data.get('configurations', {}), indent=2, default=str)[:2000]}

ALERTAS NATIVAS: {data.get('native_alerts', [])}

Detecta misconfiguraciones críticas y amenazas activas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "misconfigurations": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo Cloud"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.8),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("misconfigurations", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
