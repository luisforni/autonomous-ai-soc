"""Agente Monitor de Endpoints (EDR)."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class EndpointMonitorAgent(BaseAgent):
    name = "EndpointMonitorAgent"
    description = "Monitoreo de endpoints con capacidades EDR — procesos, conexiones, registro"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["endpoint", "edr", "process", "windows", "linux"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente EDR del AI-SOC. Monitoras endpoints y detectas:
- Procesos maliciosos y living-off-the-land (LOLBins)
- Inyección de procesos y process hollowing
- Persistencia (registry, cron, startup)
- Conexiones de red sospechosas desde procesos
- Acceso a credenciales (LSASS dump, mimikatz)
- PowerShell/CMD malicioso y obfuscación
- Movimiento lateral desde el endpoint

Responde en JSON: risk_score, endpoint_summary, suspicious_processes, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la actividad del siguiente endpoint:

HOSTNAME: {data.get('hostname', 'unknown')}
OS: {data.get('os', 'Windows')}
USUARIO ACTIVO: {data.get('active_user', 'unknown')}

PROCESOS EN EJECUCIÓN:
{json.dumps(data.get('processes', [])[:50], indent=2, default=str)[:3000]}

CONEXIONES DE RED:
{json.dumps(data.get('network_connections', [])[:30], indent=2, default=str)[:1500]}

EVENTOS RECIENTES:
{json.dumps(data.get('events', [])[:50], indent=2, default=str)[:1500]}

Detecta comportamiento malicioso y amenazas en el endpoint."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "suspicious_processes": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Actividad Maliciosa en Endpoint"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.MALWARE,
                confidence=a.get("confidence", 0.8),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("suspicious_processes", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
