"""Agente Container Registry Security."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ContainerRegistryAgent(BaseAgent):
    name = "ContainerRegistryAgent"
    description = "Seguridad en registros de contenedores — acceso, escaneo, firmado de imágenes"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.MEDIUM
    tags = ["registry", "docker-hub", "ecr", "acr", "gcr", "images"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Seguridad de Registros de Contenedores del AI-SOC. Analizas:
- Acceso público no autorizado al registry
- Imágenes sin firmar (Notary/Cosign)
- Pull/Push de imágenes desde IPs inusuales
- Imágenes con CVEs críticos en producción
- Políticas de retención de imágenes
- Credenciales de registry expuestas en builds
- Registry privado sin autenticación robusta

Responde en JSON: risk_score, registry_findings, vulnerable_images, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del registro de contenedores:

REGISTRY: {data.get('registry_url', 'unknown')}
TIPO: {data.get('registry_type', 'Docker Hub')}

IMÁGENES CON CVEs:
{json.dumps(data.get('vulnerable_images', [])[:20], indent=2, default=str)[:2000]}

ACCESOS RECIENTES:
{json.dumps(data.get('access_logs', [])[:20], indent=2, default=str)[:1000]}

IMÁGENES SIN FIRMA: {data.get('unsigned_images', [])}

Detecta riesgos en el registry."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "registry_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo en Registry"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.SUPPLY_CHAIN,
                confidence=a.get("confidence", 0.83),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("registry_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.83,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
