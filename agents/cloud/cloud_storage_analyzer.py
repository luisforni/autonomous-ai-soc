"""Agente Cloud Storage Analyzer."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class CloudStorageAnalyzerAgent(BaseCloudAgent):
    name = "CloudStorageAnalyzerAgent"
    description = "Análisis de almacenamiento cloud multi-proveedor — exposición, cifrado, compliance"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "multi-cloud"
    tags = ["storage", "s3", "blob", "gcs", "data-exposure"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Almacenamiento Cloud del AI-SOC. Detectas riesgos en:
- S3 (AWS), Blob Storage (Azure), Cloud Storage (GCP)
- Contenedores/buckets con acceso público
- Datos PII, financieros o médicos expuestos
- Cifrado en reposo y en tránsito
- Políticas de retención y ciclo de vida
- Acceso entre cuentas/tenants
- Actividad de acceso inusual (volumen, horario, ubicación)

Responde en JSON: risk_score, storage_findings, exposed_resources, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el almacenamiento cloud:

PROVEEDOR: {data.get('provider', 'unknown')}
RECURSOS:
{json.dumps(data.get('storage_resources', [])[:25], indent=2, default=str)[:3000]}

ACTIVIDAD RECIENTE:
{json.dumps(data.get('access_activity', [])[:20], indent=2, default=str)[:1000]}

Detecta exposiciones de datos y misconfiguraciones."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "exposed_resources": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Almacenamiento Expuesto"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "critical")),
                category=ThreatCategory.DATA_EXFILTRATION,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("exposed_resources", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
