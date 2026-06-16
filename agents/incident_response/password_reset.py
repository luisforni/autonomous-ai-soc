"""Agente de Reset de Contraseñas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity


class PasswordResetAgent(BaseAgent):
    name = "PasswordResetAgent"
    description = "Reset automático de credenciales comprometidas — AD, cloud, aplicaciones"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.HIGH
    tags = ["password", "credentials", "reset", "ad", "azure-ad"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Reset de Credenciales del AI-SOC. Gestionas resets masivos:
- Active Directory: password reset forzado, disable, require change at next login
- Azure AD: revocación de tokens activos, MFA reset, Conditional Access
- AWS IAM: rotación de access keys, revocación de sesiones
- Aplicaciones: reset por API/LDAP
- Priorización por riesgo: cuentas admin primero
- Notificación a usuarios afectados

Responde en JSON: risk_score, accounts_to_reset, reset_priority, reset_commands, user_notifications, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera plan de reset de credenciales:

CUENTAS COMPROMETIDAS: {json.dumps(data.get('compromised_accounts', [])[:20], indent=2, default=str)[:1000]}
TIPO DE COMPROMISO: {data.get('compromise_type', 'credential_stuffing')}
PLATAFORMA: {data.get('platform', 'Active Directory')}
DOMINIO: {data.get('domain', 'unknown')}

CUENTAS ADMIN AFECTADAS: {data.get('admin_accounts', [])}
MÉTODO DE NOTIFICACIÓN: {data.get('notification_method', 'email')}

Prioriza y genera los comandos de reset."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "accounts_to_reset": [], "reset_commands": [], "alerts": []})

        alerts = [
            self._create_alert(
                title="Reset de Credenciales Requerido",
                description=f"Se requiere reset de {len(data.get('compromised_accounts', []))} cuentas comprometidas",
                severity=Severity.HIGH,
                confidence=0.95,
            )
        ] if data.get("compromised_accounts") else []

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("accounts_to_reset", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.92,
            recommendations=result.get("reset_commands", []),
            raw_ai_response=response,
        )
