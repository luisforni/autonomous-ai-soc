"""Agente Reportero Regulatorio."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class RegulatoryReporterAgent(BaseAgent):
    name = "RegulatoryReporterAgent"
    description = "Reportes regulatorios automatizados — notificaciones de brechas, GDPR, HIPAA, PCI"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.HIGH
    tags = ["regulatory", "gdpr", "hipaa", "pci", "breach-notification", "dpa"]

    def _build_system_prompt(self) -> str:
        return """Eres el Reportero Regulatorio del AI-SOC. Gestionas notificaciones obligatorias:

Plazos de notificación:
- GDPR: 72 horas a la DPA (Autoridad de Protección de Datos)
- HIPAA: 60 días al HHS (US Dept of Health)
- PCI-DSS: inmediato a la marca de tarjeta y acquiring bank
- NIS2: 24 horas (early warning), 72 horas (notificación), 30 días (informe final)
- SEC: 4 días hábiles para empresas cotizadas en EE.UU.

Preparas:
- Borrador de notificación con información requerida
- Evaluación de qué reguladores notificar
- Evidencias de mitigación para reducir multas
- Timeline de la brecha para el reporte

Responde en JSON: risk_score, notification_required, regulators_to_notify, deadlines, draft_notifications, alerts, legal_considerations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Evalúa los requisitos de notificación regulatoria:

TIPO DE INCIDENTE: {data.get('incident_type', 'data_breach')}
DATOS AFECTADOS: {data.get('affected_data_types', [])}
NÚMERO DE AFECTADOS: {data.get('affected_individuals', 0)}
PAÍSES AFECTADOS: {data.get('affected_countries', [])}

SECTOR: {data.get('sector', 'unknown')}
FECHA DEL INCIDENTE: {data.get('incident_date', 'unknown')}
FECHA DE DETECCIÓN: {data.get('detection_date', 'unknown')}

ACCIONES MITIGANTES TOMADAS: {data.get('mitigation_actions', [])}

Determina qué reguladores notificar y prepara el borrador."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "notification_required": False, "alerts": [], "draft_notifications": []})

        alerts = []
        if result.get("notification_required"):
            alerts.append(self._create_alert(
                title="Notificación Regulatoria Requerida",
                description=f"Se debe notificar a: {result.get('regulators_to_notify', [])}",
                severity=Severity.CRITICAL,
                category=ThreatCategory.COMPLIANCE,
                confidence=0.95,
            ))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("regulators_to_notify", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.92,
            recommendations=result.get("legal_considerations", []),
            raw_ai_response=response,
        )
