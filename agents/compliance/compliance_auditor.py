"""Agente Auditor de Cumplimiento — GDPR, HIPAA, PCI-DSS, ISO 27001."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, ComplianceFinding, Severity, ThreatCategory


class ComplianceAuditorAgent(BaseAgent):
    name = "ComplianceAuditorAgent"
    description = "Auditoría de cumplimiento multi-framework — GDPR, HIPAA, PCI-DSS, ISO 27001, SOC 2"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.MEDIUM
    tags = ["compliance", "gdpr", "hipaa", "pci-dss", "iso27001", "soc2", "audit"]

    FRAMEWORKS = {
        "PCI-DSS": "Datos de tarjetas de pago — 12 requisitos",
        "HIPAA": "Información médica protegida — 18 identificadores PHI",
        "GDPR": "Datos personales europeos — 99 artículos",
        "ISO 27001": "SGSI — 114 controles en 14 dominios",
        "SOC 2": "5 criterios de servicio de confianza",
        "NIS2": "Seguridad de infraestructura crítica EU",
        "DORA": "Resiliencia operacional digital — sector financiero EU",
    }

    def _build_system_prompt(self) -> str:
        return f"""Eres el Auditor de Cumplimiento del AI-SOC. Evaluás el cumplimiento de:

{json.dumps(self.FRAMEWORKS, indent=2)}

Para cada framework auditas:
1. Estado actual de los controles (passed/failed/partial)
2. Evidencias requeridas y disponibles
3. Gaps críticos que requieren acción inmediata
4. Riesgo regulatorio (multas, sanciones potenciales)
5. Plan de remediación con plazos

Responde en JSON: risk_score, framework, compliance_score, passed_controls, failed_controls, critical_gaps, regulatory_risk, remediation_plan, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Realiza auditoría de cumplimiento:

FRAMEWORK: {data.get('framework', 'PCI-DSS')}
SECTOR DEL CLIENTE: {data.get('sector', 'fintech')}
PAÍS: {data.get('country', 'Argentina')}

CONTROLES EVALUADOS:
{json.dumps(data.get('controls', [])[:30], indent=2, default=str)[:3000]}

EVIDENCIAS DISPONIBLES: {data.get('available_evidence', [])}
AUDITORÍA ANTERIOR: {data.get('previous_audit', {})}
FECHA LÍMITE: {data.get('deadline', 'próxima auditoría anual')}

Genera el reporte de auditoría con puntuación de cumplimiento."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "compliance_score": 0, "failed_controls": [], "alerts": [], "remediation_plan": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Control de Cumplimiento Fallido"),
                description=a.get("description", ""),
                severity=Severity.HIGH,
                category=ThreatCategory.COMPLIANCE,
                confidence=0.95,
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("failed_controls", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.92,
            recommendations=result.get("remediation_plan", []),
            raw_ai_response=response,
        )
