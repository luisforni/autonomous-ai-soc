"""Agente Enforcer de Políticas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class PolicyEnforcerAgent(BaseAgent):
    name = "PolicyEnforcerAgent"
    description = "Enforcement de políticas de seguridad — detección de violaciones, remediación"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.MEDIUM
    tags = ["policy", "enforcement", "violations", "iam", "configuration"]

    def _build_system_prompt(self) -> str:
        return """Eres el Enforcer de Políticas del AI-SOC. Detectas y remedias violaciones:
- Política de contraseñas: complejidad, expiración, reutilización
- Política de acceso: MFA obligatorio, sesiones, horario
- Política de datos: clasificación, cifrado, retención
- Política de endpoints: AV activo, OS actualizado, cifrado disco
- Política de red: dispositivos autorizados, segmentación
- Política de backup: frecuencia, retención, testing
- Política BYOD (Bring Your Own Device)

Responde en JSON: risk_score, policy_violations, violation_count, critical_violations, alerts, enforcement_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta violaciones de políticas:

POLÍTICAS APLICABLES:
{json.dumps(data.get('policies', [])[:10], indent=2, default=str)[:1500]}

ESTADO ACTUAL:
{json.dumps(data.get('current_state', {}), indent=2, default=str)[:2000]}

VIOLACIONES PREVIAS: {data.get('previous_violations', [])}

Detecta violaciones y genera acciones de enforcement."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "policy_violations": [], "alerts": [], "enforcement_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Violación de Política"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.COMPLIANCE,
                confidence=0.92,
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("policy_violations", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("enforcement_actions", []),
            raw_ai_response=response,
        )
