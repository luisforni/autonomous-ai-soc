"""Agente de Forense de Red."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class NetworkForensicsAgent(BaseAgent):
    name = "NetworkForensicsAgent"
    description = "Forense de red — análisis PCAP, reconstrucción de sesiones, IOCs de red"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.HIGH
    tags = ["network", "forensics", "pcap", "sessions", "traffic-analysis"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Forense de Red del AI-SOC. Analizas capturas de red:
- Reconstrucción de sesiones TCP
- Extracción de archivos transferidos (HTTP, FTP, SMB)
- Credenciales transmitidas en claro
- DNS queries y respuestas
- C2 communications patterns
- Datos exfiltrados reconstruidos
- Protocolo analysis para tunneling
- NetFlow analysis para volúmenes

Responde en JSON: risk_score, session_summary, exfiltrated_data, c2_communications, iocs, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la captura de red forense:

INCIDENTE: {data.get('incident_id', 'unknown')}
PERIODO: {data.get('capture_period', 'unknown')}
TAMAÑO: {data.get('pcap_size_mb', 0)} MB

RESUMEN DE SESIONES:
{json.dumps(data.get('sessions', [])[:20], indent=2, default=str)[:2000]}

ARCHIVOS EXTRAÍDOS: {data.get('extracted_files', [])}
ANOMALÍAS EN PROTOCOLO: {data.get('protocol_anomalies', [])}
DATOS POTENCIALMENTE EXFILTRADOS: {data.get('potential_exfil', {})}

Reconstruye lo que el atacante hizo en la red."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "c2_communications": [], "iocs": [], "alerts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Actividad Maliciosa en Red"),
                description=a.get("description", ""),
                severity=Severity.HIGH,
                category=ThreatCategory.C2,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("c2_communications", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
