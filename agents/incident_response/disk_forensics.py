"""Agente de Forense de Disco."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class DiskForensicsAgent(BaseAgent):
    name = "DiskForensicsAgent"
    description = "Forense de disco — análisis NTFS/ext4, archivos eliminados, steganografía"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.HIGH
    tags = ["disk", "forensics", "ntfs", "ext4", "deleted-files", "timeline"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Forense de Disco del AI-SOC. Analizas imágenes de disco:
- MFT analysis (Windows) / inode analysis (Linux)
- Archivos eliminados y recuperación parcial
- Timestamps (MACE): Modified, Accessed, Changed, Entry
- Alternate Data Streams (ADS) en NTFS
- Unallocated space analysis
- Slack space análisis
- Análisis de particiones y bootloader
- Log files del filesystem

Responde en JSON: risk_score, disk_findings, deleted_files_recovered, timeline, malware_artifacts, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la imagen de disco:

SISTEMA: {data.get('hostname', 'unknown')} | FILESYSTEM: {data.get('filesystem', 'NTFS')}
INCIDENTE: {data.get('incident_id', 'unknown')}

ARTEFACTOS DEL DISCO:
{json.dumps(data.get('disk_artifacts', {}), indent=2, default=str)[:3000]}

ARCHIVOS ELIMINADOS:
{json.dumps(data.get('deleted_files', [])[:20], indent=2, default=str)[:1000]}

TIMELINE (fragmento):
{json.dumps(data.get('timeline', [])[:20], indent=2, default=str)[:1000]}

Reconstruye la actividad y recupera evidencias relevantes."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "disk_findings": [], "timeline": [], "alerts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Evidencia Forense en Disco"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("disk_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
