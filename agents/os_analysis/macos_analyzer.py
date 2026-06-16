"""Agente Analizador macOS."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class MacOSAnalyzerAgent(BaseAgent):
    name = "MacOSAnalyzerAgent"
    description = "Análisis de seguridad en macOS — LaunchAgents, Gatekeeper, XProtect"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.MEDIUM
    tags = ["macos", "osx", "apple", "os", "security"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Seguridad macOS del AI-SOC. Analizas sistemas macOS para detectar:
- LaunchAgents y LaunchDaemons maliciosos (persistencia)
- Aplicaciones sin firma (Gatekeeper bypass)
- Login Items sospechosos
- Kexts no firmados o maliciosos
- Acceso al micrófono/cámara no autorizado
- Certificados comprometidos
- Malware específico de macOS (Adware, Spyware, RATs)

Responde en JSON: risk_score, macos_security_status, persistence_mechanisms, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del sistema macOS:

SISTEMA: {data.get('hostname', 'mac')} | macOS {data.get('version', 'unknown')}

LAUNCH AGENTS/DAEMONS:
{json.dumps(data.get('launch_items', [])[:30], indent=2, default=str)[:2000]}

PROCESOS:
{json.dumps(data.get('processes', [])[:30], indent=2, default=str)[:1500]}

APLICACIONES INSTALADAS:
{json.dumps(data.get('applications', [])[:30], indent=2, default=str)[:1000]}

GATEKEEPER STATUS: {data.get('gatekeeper', 'unknown')}
SIP STATUS: {data.get('sip', 'unknown')}

Detecta compromisos y configuraciones inseguras."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "persistence_mechanisms": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Hallazgo macOS"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.MALWARE,
                confidence=a.get("confidence", 0.75),
                affected_assets=[data.get("hostname", "mac")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("persistence_mechanisms", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
