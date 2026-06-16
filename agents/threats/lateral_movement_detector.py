"""Agente Detector de Movimiento Lateral."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class LateralMovementDetectorAgent(BaseAgent):
    name = "LateralMovementDetectorAgent"
    description = "Detección de movimiento lateral — Pass-the-Hash, PSExec, WMI, RDP"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["lateral-movement", "pth", "psexec", "wmi", "rdp", "smb"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Movimiento Lateral del AI-SOC. Detectas técnicas MITRE ATT&CK T1021-T1076:
- Pass-the-Hash (PtH): autenticación con NTLM hash robado
- Pass-the-Ticket (PtT): Kerberos ticket forjado
- PsExec y herramientas similares (PAExec, Impacket)
- WMI lateral (wmiexec, DCOM)
- RDP con credenciales comprometidas
- SMB lateral y Admin$ shares
- PowerShell Remoting
- SSH hopping entre servidores
- Token impersonation

Responde en JSON: risk_score, movement_technique, source_host, target_hosts, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta movimiento lateral en la red:

RED: {data.get('network_segment', 'internal')}
VENTANA TEMPORAL: {data.get('time_window', '1h')}

CONEXIONES ENTRE HOSTS:
{json.dumps(data.get('host_connections', [])[:30], indent=2, default=str)[:2000]}

AUTENTICACIONES REMOTAS:
{json.dumps(data.get('remote_auth', [])[:30], indent=2, default=str)[:2000]}

EVENTS 4648, 4624 (LOGON_TYPE 3):
{json.dumps(data.get('logon_events', [])[:20], indent=2, default=str)[:1500]}

SERVICIOS REMOTOS CREADOS: {data.get('remote_services', [])}

Detecta qué hosts están comprometidos y el path de movimiento."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "movement_technique": "unknown", "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Movimiento Lateral Detectado"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.LATERAL_MOVEMENT,
                confidence=a.get("confidence", 0.85),
                affected_assets=result.get("target_hosts", []),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"technique": result.get("movement_technique"), "source": result.get("source_host")}],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
