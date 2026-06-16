"""Agente de Bloqueo Automático de Cuentas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity


class AccountLockoutAgent(BaseAgent):
    name = "AccountLockoutAgent"
    description = "Bloqueo automático de cuentas — respuesta inmediata ante compromiso"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.CRITICAL
    tags = ["account", "lockout", "disable", "containment", "ad"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Bloqueo de Cuentas del AI-SOC. Ejecutas bloqueos de emergencia:
- Deshabilitar cuentas en AD, Azure AD, Okta, AWS IAM
- Revocar tokens activos (OAuth, JWT, SAML)
- Terminar sesiones activas
- Bloquear MFA bypass
- Registrar la acción con timestamp y justificación
- Notificar al usuario y management

Responde en JSON: risk_score, locked_accounts, active_sessions_terminated, notifications_sent, alerts, rollback_procedure."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Ejecuta bloqueo de cuentas:

CUENTAS A BLOQUEAR: {data.get('accounts', [])}
RAZÓN: {data.get('reason', 'compromiso de credenciales')}
URGENCIA: {data.get('urgency', 'inmediata')}
PLATAFORMAS: {data.get('platforms', ['Active Directory'])}

SESIONES ACTIVAS: {data.get('active_sessions', [])}
TOKENS ACTIVOS: {data.get('active_tokens', [])}

Genera los comandos de bloqueo y el procedimiento de rollback."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "locked_accounts": [], "alerts": [], "rollback_procedure": []})

        alerts = [
            self._create_alert(
                title=f"Cuentas Bloqueadas: {len(data.get('accounts', []))} afectadas",
                description=f"Bloqueo de emergencia ejecutado. Razón: {data.get('reason', 'unknown')}",
                severity=Severity.HIGH,
                confidence=0.97,
            )
        ] if data.get("accounts") else []

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("locked_accounts", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.95,
            recommendations=result.get("rollback_procedure", []),
            raw_ai_response=response,
        )
