"""Agente Monitor de Cumplimiento Continuo."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ComplianceMonitorAgent(BaseAgent):
    name = "ComplianceMonitorAgent"
    description = "Monitoreo continuo de cumplimiento regulatorio — GDPR, HIPAA, PCI-DSS, ISO 27001"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.MEDIUM
    tags = ["compliance", "gdpr", "hipaa", "pci-dss", "iso27001", "regulatory"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Cumplimiento del AI-SOC. Verificas el cumplimiento en tiempo real de:
- GDPR: protección de datos personales, consentimiento, retención
- HIPAA: PHI, accesos a registros médicos, audit trails
- PCI-DSS: datos de tarjetas, cifrado, segmentación de red
- ISO 27001: controles de seguridad de la información
- SOC 2: disponibilidad, confidencialidad, integridad
- NIS2: seguridad de infraestructura crítica

Responde en JSON: risk_score, compliance_frameworks, violations, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el siguiente evento para verificar cumplimiento regulatorio:

FRAMEWORK APLICABLE: {data.get('framework', 'PCI-DSS')}
SECTOR: {data.get('sector', 'fintech')}
EVENTO: {json.dumps(data.get('event', {}), indent=2, default=str)}

CONTROLES EVALUADOS: {data.get('controls', [])}
CONFIGURACIÓN ACTUAL: {json.dumps(data.get('configuration', {}), default=str)[:2000]}

Identifica violaciones de cumplimiento y riesgos regulatorios."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "violations": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Violación de Cumplimiento"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.COMPLIANCE,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("violations", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
