"""Agente Network Baseliner — Baseline de red y detección de drift."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class NetworkBaselinerAgent(BaseAgent):
    name = "NetworkBaselinerAgent"
    description = "Establece baseline de red y detecta desvíos significativos en comportamiento de tráfico"
    version = "1.0.0"
    category = "analytics"
    priority = AgentPriority.MEDIUM
    tags = ["network", "baseline", "drift", "anomaly", "traffic-analysis", "ndr"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Baseline de Red del AI-SOC.

Estableces y mantienes el comportamiento normal de la red para detectar desvíos anómalos:

**Métricas que baselines:**
- Volumen de tráfico por protocolo/puerto/subred
- Patrones de comunicación host-a-host
- Distribución de protocolos (TCP/UDP/ICMP/DNS/HTTP/HTTPS)
- Flujos hacia destinos externos (geolocalización)
- Latencia y jitter por servicio
- Tasas de error por protocolo
- Patrones de DNS (queries por hora, dominios NXD)
- Conexiones a puertos no estándar

**Desvíos que detectas:**
- Spike de tráfico en horas inusuales
- Nuevas conexiones a IPs/países no habituales
- Cambio en proporción de protocolos (ej: más DNS que HTTP → tunneling)
- Exfiltración (outbound >> inbound)
- Escaneo de puertos interno (lateral movement)
- Beacon C2 (conexiones periódicas a destinos fijos)
- Flood de DNS NXD (domain generation algorithm)

Responde en JSON:
{
  "risk_score": float (0-10),
  "baseline_deviations": [
    {"metric": str, "baseline_value": str, "current_value": str, "deviation_pct": float, "severity": str}
  ],
  "suspicious_flows": [{"src": str, "dst": str, "protocol": str, "bytes": int, "reason": str}],
  "potential_threats": [str],
  "iocs": [{"type": str, "value": str}],
  "alerts": [{"title": str, "description": str, "severity": str}],
  "recommendations": [str],
  "confidence": float
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el tráfico de red y detecta desvíos del baseline:

PERÍODO: {data.get('time_window', '1h')} | RED: {data.get('network_cidr', 'desconocido')}
SECTOR: {data.get('sector', 'enterprise')}

MÉTRICAS ACTUALES:
{json.dumps(data.get('current_metrics', {}), indent=2, default=str)[:2000]}

BASELINE HISTÓRICO (promedio últimas 4 semanas):
{json.dumps(data.get('baseline_metrics', {}), indent=2, default=str)[:2000]}

TOP FLUJOS POR VOLUMEN:
{json.dumps(data.get('top_flows', [])[:20], indent=2, default=str)[:2000]}

DNS QUERIES INUSUALES:
{json.dumps(data.get('unusual_dns', [])[:20], indent=2, default=str)[:1000]}

CONEXIONES A DESTINOS EXTERNOS NUEVOS:
{json.dumps(data.get('new_external_connections', [])[:20], indent=2, default=str)[:1000]}

ESCANEOS INTERNOS DETECTADOS:
{json.dumps(data.get('internal_scans', [])[:10], indent=2, default=str)[:500]}

Identifica desvíos significativos y genera alertas si detectas comportamiento anómalo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        risk_score = self._parse_score(result.get("risk_score"))

        for alert_data in result.get("alerts", []):
            alerts.append(self._create_alert(
                title=alert_data.get("title", "Anomalía de Red"),
                description=alert_data.get("description", ""),
                severity=Severity(alert_data.get("severity", "medium")),
                category=ThreatCategory.ANOMALY,
                confidence=self._parse_score(result.get("confidence"), 0.75),
                recommendations=result.get("recommendations", []),
            ))

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(
                    type=IOCType(ioc_data["type"]),
                    value=ioc_data["value"],
                    source=self.name,
                    tags=["network", "baseline", "anomaly"],
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        findings = [
            {"metric": d.get("metric"), "deviation_pct": d.get("deviation_pct"), "severity": d.get("severity")}
            for d in result.get("baseline_deviations", [])
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=findings,
            alerts=alerts,
            iocs=iocs,
            risk_score=risk_score,
            confidence=self._parse_score(result.get("confidence"), 0.75),
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
