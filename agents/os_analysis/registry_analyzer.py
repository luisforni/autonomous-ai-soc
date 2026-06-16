"""Agente Analizador del Registro de Windows."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class RegistryAnalyzerAgent(BaseAgent):
    name = "RegistryAnalyzerAgent"
    description = "Análisis del registro de Windows — persistencia, malware, configuraciones inseguras"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.HIGH
    tags = ["registry", "windows", "persistence", "malware", "forensics"]

    PERSISTENCE_KEYS = [
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Registro Windows del AI-SOC. Detectas en el registro:
- Malware con persistencia vía Run/RunOnce keys
- Backdoors en Image File Execution Options (IFEO)
- Servicios maliciosos instalados
- Hijacking de COM Objects
- AppInit_DLLs maliciosas
- Winlogon Notify handlers
- Browser Helper Objects (BHOs)
- Drivers maliciosos en HKLM\\SYSTEM\\CurrentControlSet\\Services

Responde en JSON: risk_score, suspicious_keys, malware_persistence, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las siguientes claves del registro de Windows:

HOSTNAME: {data.get('hostname', 'unknown')}

CLAVES DE PERSISTENCIA:
{json.dumps(data.get('persistence_keys', {}), indent=2, default=str)[:3000]}

CAMBIOS RECIENTES EN REGISTRO:
{json.dumps(data.get('recent_changes', [])[:30], indent=2, default=str)[:2000]}

CLAVES DE AUTORUN EXTERNAS:
{json.dumps(data.get('autoruns', [])[:20], indent=2, default=str)[:1000]}

RUTAS MONITOREADAS: {self.PERSISTENCE_KEYS[:3]}

Detecta persistencia maliciosa y configuraciones comprometidas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "suspicious_keys": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Persistencia Maliciosa en Registro"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.MALWARE,
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("suspicious_keys", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
