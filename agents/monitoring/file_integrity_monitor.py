"""Agente Monitor de Integridad de Archivos (FIM)."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class FileIntegrityMonitorAgent(BaseAgent):
    name = "FileIntegrityMonitorAgent"
    description = "Monitoreo de integridad de archivos críticos del sistema (FIM)"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["fim", "files", "integrity", "rootkit", "tamper"]

    CRITICAL_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/bin/", "/sbin/", "/usr/bin/", "/boot/",
        "C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\",
        "HKLM\\SYSTEM\\", "HKLM\\SOFTWARE\\",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Integridad de Archivos del AI-SOC. Analizas cambios en el filesystem para detectar:
- Modificaciones no autorizadas en archivos críticos del sistema
- Instalación de rootkits y backdoors
- Alteración de binarios del sistema
- Cambios en archivos de configuración de seguridad
- Creación de archivos maliciosos en directorios sensibles
- Permisos incorrectos o SUID/SGID no autorizados

Responde en JSON: risk_score, changes_analyzed, critical_changes, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza los siguientes cambios detectados en el filesystem:

CAMBIOS DETECTADOS:
{json.dumps(data.get('changes', []), indent=2, default=str)[:4000]}

SISTEMA OPERATIVO: {data.get('os', 'Linux')}
HOSTNAME: {data.get('hostname', 'desconocido')}
PERIODO: {data.get('time_range', 'último 1h')}
RUTAS CRÍTICAS MONITOREADAS: {self.CRITICAL_PATHS[:5]}

Determina qué cambios son maliciosos o sospechosos y genera alertas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Cambio Sospechoso Detectado"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.MALWARE,
                confidence=a.get("confidence", 0.8),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for change in result.get("critical_changes", []):
            if isinstance(change, dict) and change.get("hash"):
                iocs.append(IOC(
                    type=IOCType.FILE_HASH_SHA256,
                    value=change.get("hash", ""),
                    confidence=0.8,
                    source=self.name,
                ))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("critical_changes", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
