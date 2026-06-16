"""Agente Analizador de Paquetes — Deep Packet Inspection."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class PacketAnalyzerAgent(BaseAgent):
    name = "PacketAnalyzerAgent"
    description = "Inspección profunda de paquetes (DPI) para detección de amenazas"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["packets", "dpi", "pcap", "network", "forensics"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Paquetes DPI del AI-SOC. Realizas inspección profunda de paquetes para detectar:
- Payloads maliciosos y exploits
- Protocolos no autorizados
- Tunneling y evasión
- Exfiltración de datos en protocolos permitidos
- Anomalías en headers de protocolos
- Shellcode y exploits en tráfico de red

Responde en JSON con: risk_score, packet_summary, alerts, iocs, protocol_anomalies, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la siguiente captura de paquetes:

RESUMEN DE PAQUETES:
{json.dumps(data.get('packet_summary', data), indent=2, default=str)[:4000]}

PROTOCOLOS DETECTADOS: {data.get('protocols', [])}
PUERTOS DESTINO: {data.get('dst_ports', [])}

Detecta payloads maliciosos, anomalías de protocolo y amenazas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Anomalía de Paquetes"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.7),
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
            findings=result.get("protocol_anomalies", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.8,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
