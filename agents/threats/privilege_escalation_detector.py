"""Agente Detector de Escalada de Privilegios."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class PrivilegeEscalationDetectorAgent(BaseAgent):
    name = "PrivilegeEscalationDetectorAgent"
    description = "Detección de escalada de privilegios — kernel exploits, SUID, sudo, token impersonation"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["privilege-escalation", "sudo", "suid", "kernel", "t1068", "mitre"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Escalada de Privilegios del AI-SOC. Detectas MITRE ATT&CK TA0004:

En Linux:
- Kernel exploits (Dirty Cow, Dirty Pipe, OverlayFS)
- SUID/SGID binaries abuse
- Sudo misconfigurations (sudoers NOPASSWD)
- Writeable /etc/passwd o /etc/sudoers
- PATH manipulation
- LD_PRELOAD injection
- Cron jobs con archivos modificables por usuario

En Windows:
- UAC bypass techniques
- Token impersonation (Incognito, Potato attacks)
- DLL hijacking
- AlwaysInstallElevated
- Unquoted service paths
- Weak service permissions
- Stored credentials (cmdkey, credential manager)

Responde en JSON: risk_score, escalation_technique, from_user, to_user, os_type, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta escalada de privilegios:

SISTEMA: {data.get('hostname', 'unknown')} | OS: {data.get('os', 'Linux')}
USUARIO INICIAL: {data.get('initial_user', 'unknown')}
USUARIO ACTUAL: {data.get('current_user', 'unknown')}

COMANDOS EJECUTADOS:
{json.dumps(data.get('commands', [])[:30], indent=2, default=str)[:2000]}

EVENTOS DE PRIVILEGIO:
{json.dumps(data.get('privilege_events', [])[:20], indent=2, default=str)[:1500]}

PROCESOS CON ROOT/SYSTEM:
{json.dumps(data.get('elevated_processes', [])[:15], indent=2, default=str)[:1000]}

SUID BINARIES ACCEDIDOS: {data.get('suid_accessed', [])}

Detecta la técnica de escalada y el impacto."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "escalation_technique": "unknown", "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Escalada de Privilegios Detectada"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                confidence=a.get("confidence", 0.87),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"technique": result.get("escalation_technique"), "from": result.get("from_user"), "to": result.get("to_user")}],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
