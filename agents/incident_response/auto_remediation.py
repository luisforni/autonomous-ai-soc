"""Agente de Remediación Automática."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class AutoRemediationAgent(BaseAgent):
    name = "AutoRemediationAgent"
    description = "Remediación automática de amenazas — bloqueo, aislamiento, limpieza, restauración"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.CRITICAL
    tags = ["remediation", "automation", "soar", "playbook", "response"]

    SAFE_AUTO_ACTIONS = [
        "block_ip_firewall",
        "disable_user_account",
        "revoke_api_key",
        "quarantine_file",
        "terminate_process",
        "block_domain_dns",
        "revoke_session_tokens",
    ]

    REQUIRES_APPROVAL = [
        "isolate_host_network",
        "shutdown_instance",
        "restore_from_backup",
        "reset_password_bulk",
        "block_entire_subnet",
    ]

    def _build_system_prompt(self) -> str:
        return f"""Eres el Agente de Remediación Automática del AI-SOC. Ejecutas acciones de respuesta:

Acciones automáticas (sin aprobación):
{self.SAFE_AUTO_ACTIONS}

Acciones que requieren aprobación:
{self.REQUIRES_APPROVAL}

Para cada amenaza:
1. Determinas las acciones de remediación apropiadas
2. Evalúas el impacto en el negocio
3. Propones acciones automáticas vs manuales
4. Generas comandos/scripts específicos para ejecutar
5. Verificas el éxito de las acciones

Responde en JSON: risk_score, auto_actions, manual_actions, remediation_commands, expected_impact, verification_steps, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera plan de remediación automática:

TIPO DE AMENAZA: {data.get('threat_type', 'unknown')}
SEVERIDAD: {data.get('severity', 'high')}
SISTEMAS AFECTADOS: {data.get('affected_systems', [])}
USUARIO COMPROMETIDO: {data.get('compromised_user', 'unknown')}
IP MALICIOSA: {data.get('malicious_ip', 'unknown')}

AMENAZAS ACTIVAS:
{json.dumps(data.get('active_threats', [])[:10], indent=2, default=str)[:2000]}

CONSTRAINTS DEL NEGOCIO: {data.get('business_constraints', 'producción 24/7')}
APROBACIÓN DISPONIBLE: {data.get('approval_available', False)}

Genera las acciones de remediación con scripts específicos."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "auto_actions": [], "manual_actions": [], "alerts": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Remediación Ejecutada"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("auto_actions", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("manual_actions", []),
            raw_ai_response=response,
        )
