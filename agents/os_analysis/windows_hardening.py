"""Agente de Hardening Windows — CIS Benchmarks."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class WindowsHardeningAgent(BaseAgent):
    name = "WindowsHardeningAgent"
    description = "Verificación de hardening Windows según CIS Benchmarks y DISA STIG"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.MEDIUM
    tags = ["hardening", "windows", "cis", "stig", "gpo", "baseline"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Hardening Windows del AI-SOC. Verificas configuraciones según:
- CIS Benchmark para Windows Server 2019/2022 y Windows 10/11
- DISA STIG para Windows
- Microsoft Security Baselines

Evalúas:
- GPO y políticas de seguridad locales
- Windows Defender y AV status
- Firewall de Windows
- UAC configuration
- RDP security settings
- SMB signing y versiones
- PowerShell execution policy y logging
- LAPS (Local Admin Password Solution)
- Windows Update status
- AppLocker/WDAC policies
- Credential Guard / Device Guard

Responde en JSON: risk_score, hardening_score, failed_controls, passed_controls, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Evalúa el hardening del sistema Windows:

SISTEMA: {data.get('hostname', 'unknown')} | {data.get('os_version', 'Windows')}
DOMINIO: {data.get('domain', 'WORKGROUP')}

POLÍTICAS DE SEGURIDAD:
{json.dumps(data.get('security_policies', {}), indent=2, default=str)[:2000]}

WINDOWS DEFENDER: {json.dumps(data.get('defender_status', {}), default=str)}
FIREWALL: {json.dumps(data.get('firewall', {}), default=str)}
SMB STATUS: {data.get('smb_status', 'unknown')}
RDP STATUS: {data.get('rdp_status', 'unknown')}
UAC LEVEL: {data.get('uac_level', 'unknown')}
WINDOWS UPDATE: {json.dumps(data.get('updates', {}), default=str)}

Evalúa los controles de hardening críticos."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 5, "hardening_score": 50, "alerts": [], "failed_controls": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Control Windows Fallido"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.VULNERABILITY,
                confidence=0.95,
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("failed_controls", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.92,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
