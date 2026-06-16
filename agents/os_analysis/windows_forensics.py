"""Agente de Forense Digital Windows."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class WindowsForensicsAgent(BaseAgent):
    name = "WindowsForensicsAgent"
    description = "Forense digital en Windows — prefetch, registro, NTFS, artefactos"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.HIGH
    tags = ["forensics", "windows", "incident", "prefetch", "registry", "ntfs"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Forense Digital Windows del AI-SOC. Analizas artefactos Windows:
- Prefetch files (ejecución de programas)
- ShellBags (navegación de carpetas)
- LNK files y Jump Lists
- MFT ($MFT) análisis
- Registro de Windows: UserAssist, RecentDocs, TypedURLs
- SAM y NTDS.dit (hashes de contraseñas)
- VSS (Volume Shadow Copies)
- Memory artifacts: pagefile.sys, hiberfil.sys
- Browser artifacts
- RDP/WEF logs

Responde en JSON: risk_score, timeline, windows_artifacts, iocs, attack_path, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Realiza análisis forense Windows:

SISTEMA: {data.get('hostname', 'unknown')}
INCIDENTE: {data.get('incident_id', 'unknown')}

ARTEFACTOS WINDOWS:
{json.dumps(data.get('artifacts', {}), indent=2, default=str)[:4000]}

EVENTOS DE SEGURIDAD CLAVE:
{json.dumps(data.get('security_events', [])[:30], indent=2, default=str)[:2000]}

Reconstruye el ataque y recolecta todas las evidencias."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "windows_artifacts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Evidencia Forense Windows"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name, confidence=0.8))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("windows_artifacts", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
