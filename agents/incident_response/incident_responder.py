"""Agente Coordinador de Respuesta a Incidentes."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Incident, IncidentStatus, Severity, ThreatCategory


class IncidentResponderAgent(BaseAgent):
    name = "IncidentResponderAgent"
    description = "Coordinador principal de respuesta a incidentes — triage, escalada, coordinación"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.CRITICAL
    tags = ["incident-response", "ir", "triage", "playbook", "coordination"]

    PLAYBOOKS = {
        "ransomware": ["isolate", "preserve_evidence", "notify_management", "engage_forensics", "assess_backup"],
        "data_breach": ["identify_scope", "contain", "notify_dpa", "forensics", "remediate"],
        "apt": ["dont_tip_off", "preserve_evidence", "silent_monitoring", "escalate_to_ciso"],
        "ddos": ["activate_scrubbing", "notify_isp", "failover", "document"],
        "phishing": ["revoke_credentials", "block_sender", "scan_endpoints", "user_awareness"],
    }

    def _build_system_prompt(self) -> str:
        return f"""Eres el Coordinador Principal de Respuesta a Incidentes del AI-SOC. Gestionas el ciclo completo:

1. TRIAGE: clasificación inicial, severidad, impacto
2. CONTENCIÓN: acciones inmediatas para limitar el daño
3. ERRADICACIÓN: eliminar el vector de ataque
4. RECUPERACIÓN: restaurar operaciones normales
5. POST-INCIDENTE: lecciones aprendidas

Playbooks disponibles: {list(self.PLAYBOOKS.keys())}

Para cada incidente generas:
- Plan de respuesta priorizado
- Comunicaciones (management, legal, clientes, reguladores)
- Acciones técnicas inmediatas
- SLA y métricas de seguimiento (MTTD, MTTR)

Responde en JSON: risk_score, incident_classification, severity, response_plan, immediate_actions, communications, timeline, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Coordina la respuesta al incidente:

TIPO DE INCIDENTE: {data.get('incident_type', 'unknown')}
SEVERIDAD INICIAL: {data.get('initial_severity', 'unknown')}
HORA DE DETECCIÓN: {data.get('detection_time', 'unknown')}
SISTEMAS AFECTADOS: {data.get('affected_systems', [])}
SECTOR DEL CLIENTE: {data.get('sector', 'unknown')}

DESCRIPCIÓN:
{str(data.get('description', ''))[:1000]}

ALERTAS RELACIONADAS:
{json.dumps(data.get('related_alerts', [])[:10], indent=2, default=str)[:1500]}

ACCIONES YA TOMADAS: {data.get('actions_taken', [])}

Genera el plan de respuesta completo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "response_plan": {}, "immediate_actions": [], "alerts": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Acción de Respuesta Requerida"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "critical")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.9),
                affected_assets=data.get("affected_systems", []),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[result.get("response_plan", {})],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
