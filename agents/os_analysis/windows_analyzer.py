"""Agente Analizador Windows — seguridad completa de sistemas Windows."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class WindowsAnalyzerAgent(BaseAgent):
    name = "WindowsAnalyzerAgent"
    description = "Análisis de seguridad profundo en sistemas Windows — Event Log, registro, procesos"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.HIGH
    tags = ["windows", "os", "event-log", "registry", "powershell"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Seguridad Windows del AI-SOC. Realizas análisis completos en Windows:

Analizas:
- Windows Event Log (Security, System, Application, PowerShell)
- Procesos activos y árbol de procesos
- Registro de Windows (Run, RunOnce, Services, Scheduled Tasks)
- Conexiones de red y puertos
- Cuentas de usuario y grupos (AD, local)
- Servicios instalados y drivers
- AppLocker, Windows Defender, UAC
- PowerShell history y scripts
- WMI persistencia
- Indicadores de compromise en memoria

Responde en JSON: risk_score, system_info, event_log_findings, registry_findings, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del siguiente sistema Windows:

SISTEMA: {data.get('hostname', 'unknown')} | {data.get('os_version', 'Windows')}
DOMINIO: {data.get('domain', 'WORKGROUP')}

EVENTOS CRÍTICOS (Security):
{json.dumps(data.get('security_events', [])[:50], indent=2, default=str)[:2500]}

PROCESOS:
{json.dumps(data.get('processes', [])[:40], indent=2, default=str)[:1500]}

CLAVES DE REGISTRO SOSPECHOSAS:
{json.dumps(data.get('registry_keys', [])[:20], indent=2, default=str)[:1000]}

SERVICIOS:
{json.dumps(data.get('services', [])[:30], indent=2, default=str)[:1000]}

SCHEDULED TASKS:
{json.dumps(data.get('scheduled_tasks', [])[:20], indent=2, default=str)[:500]}

Identifica compromisos, malware, persistencia y configuraciones inseguras."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "event_log_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Hallazgo de Seguridad Windows"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.8),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        def _to_list(v): return v if isinstance(v, list) else (list(v.values()) if isinstance(v, dict) else [])
        findings = _to_list(result.get("event_log_findings")) + _to_list(result.get("registry_findings"))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=findings,
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
