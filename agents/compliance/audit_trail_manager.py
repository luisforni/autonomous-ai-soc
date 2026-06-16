"""Agente Gestor de Pistas de Auditoría."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class AuditTrailManagerAgent(BaseAgent):
    name = "AuditTrailManagerAgent"
    description = "Gestión de pistas de auditoría — integridad, retención, exportación para compliance"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.MEDIUM
    tags = ["audit-trail", "logging", "immutable", "compliance", "forensics"]

    def _build_system_prompt(self) -> str:
        return """Eres el Gestor de Pistas de Auditoría del AI-SOC. Garantizas la integridad de logs:
- Logs inmutables: WORM storage, blockchain logging
- Retención según regulación: PCI-DSS 1 año, HIPAA 6 años, GDPR 3 meses
- Integridad: hash chaining de log entries
- Cobertura: qué sistemas tienen logging vs cuáles no
- Exportación para auditorías externas
- Alertas de manipulación o borrado de logs
- Log management: retención, compresión, archivado

Responde en JSON: risk_score, audit_coverage, retention_status, integrity_status, gaps, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Evalúa las pistas de auditoría:

FRAMEWORK: {data.get('compliance_framework', 'PCI-DSS')}
SISTEMAS CON LOGGING: {data.get('systems_with_logs', [])}
SISTEMAS SIN LOGGING: {data.get('systems_without_logs', [])}

ESTADO DE RETENCIÓN:
{json.dumps(data.get('retention_status', {}), indent=2, default=str)}

ALERTAS DE INTEGRIDAD: {data.get('integrity_alerts', [])}
ANOMALÍAS DE LOGS: {data.get('log_anomalies', [])}

Detecta gaps y riesgos en las pistas de auditoría."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "gaps": [], "alerts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Gap en Pistas de Auditoría"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.COMPLIANCE,
                confidence=0.92,
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("gaps", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
