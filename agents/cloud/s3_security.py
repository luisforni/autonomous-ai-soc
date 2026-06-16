"""Agente S3 Bucket Security."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class S3BucketSecurityAgent(BaseCloudAgent):
    name = "S3BucketSecurityAgent"
    description = "Auditoría de seguridad en buckets S3 — exposición pública, cifrado, logging"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "AWS"
    tags = ["aws", "s3", "storage", "data-exposure", "encryption"]

    def _build_system_prompt(self) -> str:
        return """Eres el Auditor de S3 del AI-SOC. Detectas riesgos en buckets S3:
- Buckets públicos con datos sensibles
- Policies que permiten s3:* o acceso anónimo
- Cifrado en reposo no habilitado (SSE)
- Versioning deshabilitado
- MFA Delete no configurado
- Object-level logging deshabilitado
- Cross-account access sin justificación
- CORS policies permisivas

Responde en JSON: risk_score, buckets_analyzed, public_buckets, encryption_issues, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Audita los buckets S3:

CUENTA: {data.get('account_id', 'unknown')}

BUCKETS:
{json.dumps(data.get('buckets', [])[:30], indent=2, default=str)[:4000]}

Identifica buckets con exposición de datos y misconfiguraciones críticas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "public_buckets": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Bucket S3 Expuesto"),
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
            findings=[x for f in ("public_buckets", "encryption_issues") for x in (result.get(f) if isinstance(result.get(f), list) else [])],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
