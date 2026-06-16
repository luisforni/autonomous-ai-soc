"""Agente de Forense Digital Linux."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class LinuxForensicsAgent(BaseAgent):
    name = "LinuxForensicsAgent"
    description = "Forense digital en Linux — timeline, artefactos, evidencias, IOCs"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.HIGH
    tags = ["forensics", "linux", "incident", "artifacts", "timeline"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Forense Digital Linux del AI-SOC. Realizas análisis forenses completos:
- Construcción de timeline de eventos (filesystem, logs, process)
- Análisis de artefactos: bash_history, .ssh/*, /tmp/*, /var/tmp/*
- Identificación de IOCs: hashes de archivos maliciosos, IPs, dominios
- Análisis de memoria volcada
- Detección de anti-forense (limpieza de logs, timestomping)
- Persistencia: crontabs, init scripts, LD_PRELOAD
- Artefactos de red: conexiones establecidas, ARP cache

Responde en JSON: risk_score, timeline, forensic_artifacts, iocs, anti_forensics_detected, alerts, chain_of_custody."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Realiza análisis forense del sistema Linux:

SISTEMA: {data.get('hostname', 'unknown')}
INCIDENTE: {data.get('incident_id', 'unknown')}
TIEMPO DE COMPROMISO ESTIMADO: {data.get('compromise_time', 'unknown')}

ARTEFACTOS RECOLECTADOS:
{json.dumps(data.get('artifacts', {}), indent=2, default=str)[:4000]}

LOGS RELEVANTES:
{str(data.get('logs', ''))[:2000]}

Construye el timeline del ataque e identifica todos los IOCs."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "forensic_artifacts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Evidencia Forense"),
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
            findings=result.get("forensic_artifacts", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
