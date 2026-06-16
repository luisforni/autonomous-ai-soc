"""Agente Analizador Linux — seguridad y hardening de sistemas Linux."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class LinuxAnalyzerAgent(BaseAgent):
    name = "LinuxAnalyzerAgent"
    description = "Análisis de seguridad profundo en sistemas Linux — procesos, red, archivos, usuarios"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.HIGH
    tags = ["linux", "unix", "os", "hardening", "forensics"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Seguridad Linux del AI-SOC. Realizas análisis completos de seguridad en sistemas Linux:

Analizas:
- Procesos activos y sus conexiones de red (netstat, ss, /proc)
- Usuarios y grupos (passwd, shadow, sudoers)
- Servicios activos y puertos abiertos
- Crontabs y tareas programadas
- Módulos del kernel cargados
- Archivos con SUID/SGID
- Conexiones de red establecidas
- Logs del sistema (/var/log/)
- Configuración de SSH, PAM, SELinux/AppArmor
- Backdoors y persistencia

Responde en JSON: risk_score, os_info, security_findings, suspicious_processes, suspicious_users, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del siguiente sistema Linux:

SISTEMA: {data.get('hostname', 'unknown')} | {data.get('os_version', 'Linux')}
KERNEL: {data.get('kernel', 'unknown')}
UPTIME: {data.get('uptime', 'unknown')}

PROCESOS ACTIVOS:
{json.dumps(data.get('processes', [])[:50], indent=2, default=str)[:2000]}

CONEXIONES DE RED:
{json.dumps(data.get('network', [])[:30], indent=2, default=str)[:1500]}

USUARIOS:
{json.dumps(data.get('users', [])[:20], indent=2, default=str)[:1000]}

CRONTABS:
{json.dumps(data.get('crontabs', []), indent=2, default=str)[:500]}

SERVICIOS ACTIVOS:
{json.dumps(data.get('services', [])[:30], indent=2, default=str)[:1000]}

ÚLTIMOS LOGINS:
{json.dumps(data.get('last_logins', [])[:20], indent=2, default=str)[:500]}

Identifica compromisos de seguridad, persistencia maliciosa y configuraciones inseguras."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "security_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Hallazgo de Seguridad Linux"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.8),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("security_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
