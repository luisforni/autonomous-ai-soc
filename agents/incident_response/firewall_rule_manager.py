"""Agente Gestor de Reglas de Firewall."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity


class FirewallRuleManagerAgent(BaseAgent):
    name = "FirewallRuleManagerAgent"
    description = "Gestión dinámica de reglas de firewall — bloqueo de IPs, actualización en tiempo real"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.CRITICAL
    tags = ["firewall", "rules", "blocking", "ips", "network-security"]

    def _build_system_prompt(self) -> str:
        return """Eres el Gestor de Reglas de Firewall del AI-SOC. Gestionas reglas en tiempo real:
- Bloqueo de IPs maliciosas en perimeter firewall
- Block lists dinámicas (IP reputation feeds)
- Reglas temporales con expiración automática
- Whitelisting de falsos positivos
- Sincronización entre múltiples firewalls (Palo Alto, Fortinet, CheckPoint, pfSense)
- Reglas de geo-blocking
- Rate limiting dinámico

Responde en JSON: risk_score, rules_to_add, rules_to_remove, firewall_commands, expected_impact, rollback_commands, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Gestiona las reglas de firewall:

TIPO DE FIREWALL: {data.get('firewall_type', 'iptables')}
IPs A BLOQUEAR: {data.get('block_ips', [])}
IPs A PERMITIR (whitelist): {data.get('allow_ips', [])}
PUERTOS A BLOQUEAR: {data.get('block_ports', [])}
DURACIÓN DEL BLOQUEO: {data.get('block_duration', 'permanente')}
DIRECCIÓN: {data.get('direction', 'inbound')}

REGLAS ACTUALES:
{json.dumps(data.get('current_rules', [])[:10], indent=2, default=str)[:1000]}

Genera los comandos específicos para el tipo de firewall."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "rules_to_add": [], "firewall_commands": [], "alerts": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("rules_to_add", []),
            alerts=[],
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.93,
            recommendations=result.get("firewall_commands", []),
            raw_ai_response=response,
        )
