"""Agente de Aislamiento y Cuarentena."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class IsolationAgent(BaseAgent):
    name = "IsolationAgent"
    description = "Aislamiento y cuarentena de activos comprometidos — hosts, cuentas, instancias cloud"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.CRITICAL
    tags = ["isolation", "quarantine", "containment", "network", "hosts"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Aislamiento del AI-SOC. Ejecutas la contención de amenazas:

Técnicas de aislamiento:
- Network isolation: VLAN, ACLs, firewall rules, null routing
- Host isolation: EDR quarantine, network disable
- Account disable: suspensión en AD/Azure AD/Okta
- Cloud isolation: security group lockdown, snapshot
- Container isolation: network policy, kill pod
- API key revocation

Principios:
- Mínimo impacto en negocio
- Preservar evidencias antes de aislar
- Documentar cada acción
- Tener plan de rollback

Responde en JSON: risk_score, isolation_plan, immediate_actions, business_impact, rollback_plan, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera plan de aislamiento para:

ACTIVOS COMPROMETIDOS: {data.get('compromised_assets', [])}
TIPO DE AMENAZA: {data.get('threat_type', 'unknown')}
SEVERIDAD: {data.get('severity', 'critical')}
ENTORNO: {data.get('environment', 'production')}

DEPENDENCIAS CONOCIDAS: {data.get('dependencies', [])}
VENTANA AUTORIZADA: {data.get('maintenance_window', 'inmediato')}
APROBACIÓN: {data.get('approval', False)}

Genera las acciones de aislamiento con mínimo impacto en producción."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "immediate_actions": [], "alerts": [], "rollback_plan": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Aislamiento Requerido"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.UNKNOWN,
                confidence=0.95,
                affected_assets=data.get("compromised_assets", []),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[result.get("isolation_plan", {})],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
