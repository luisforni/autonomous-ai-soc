"""Agente Monitor de Tráfico de Red."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class NetworkTrafficMonitorAgent(BaseAgent):
    name = "NetworkTrafficMonitorAgent"
    description = "Monitoreo y análisis de tráfico de red en tiempo real — detección de anomalías"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["network", "traffic", "nta", "ids", "flow"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Tráfico de Red del AI-SOC. Analizas flujos de red (NetFlow/IPFIX/sFlow) y capturas de paquetes para detectar amenazas.

Detectas: escaneos de puertos, movimiento lateral, exfiltración de datos, C2 traffic, DDoS, tunneling DNS/HTTPS, beaconing, y tráfico cifrado sospechoso.

Responde en JSON:
{
  "risk_score": float,
  "traffic_summary": {"total_flows": int, "anomalous_flows": int, "top_talkers": [str]},
  "alerts": [{"title": str, "description": str, "severity": str, "category": str, "src_ip": str, "dst_ip": str, "port": int, "protocol": str, "confidence": float, "recommendations": [str]}],
  "iocs": [{"type": str, "value": str, "confidence": float}],
  "anomalies": [{"type": str, "description": str, "severity": str}],
  "recommendations": [str]
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el siguiente tráfico de red y detecta amenazas:

DATOS DE TRÁFICO:
{json.dumps(data.get('flows', data.get('traffic', {})), indent=2, default=str)[:4000]}

BASELINE DE RED: {json.dumps(data.get('baseline', {}), default=str)}
SEGMENTO: {data.get('network_segment', 'desconocido')}

Detecta comportamientos anómalos, patrones de ataque y genera alertas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        prompt = self._build_user_prompt(data)
        response = await self._query_ai(prompt)

        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "anomalies": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Alerta de Red"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.7),
                recommendations=a.get("recommendations", []),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(
                    type=IOCType(ioc_data.get("type", "ip")),
                    value=ioc_data.get("value", ""),
                    confidence=ioc_data.get("confidence", 0.5),
                    source=self.name,
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("anomalies", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.8,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
