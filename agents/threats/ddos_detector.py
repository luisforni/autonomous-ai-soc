"""Agente Detector de DDoS."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class DDoSDetectorAgent(BaseAgent):
    name = "DDoSDetectorAgent"
    description = "Detección y análisis de ataques DDoS — volumétrico, protocolo, capa de aplicación"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["ddos", "dos", "volumetric", "amplification", "botnet"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de DDoS del AI-SOC. Detectas ataques de Denegación de Servicio:

Tipos de DDoS:
- Volumétrico: UDP flood, ICMP flood, amplification (DNS, NTP, memcached)
- Protocolo: SYN flood, Ping of Death, Smurf
- Capa de Aplicación (L7): HTTP flood, Slowloris, RUDY
- ReDoS: ataques de expresiones regulares
- API abuse: rate limit bypass

Indicadores:
- Picos de tráfico muy por encima del baseline
- Muchas conexiones SYN sin completar (half-open)
- IPs de múltiples países simultáneamente
- Tráfico con mismo User-Agent o payload repetitivo
- Botnets IoT comprometidas

Responde en JSON: risk_score, attack_type, attack_vector, traffic_gbps, source_ips, alerts, mitigation_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el posible ataque DDoS:

SERVICIO OBJETIVO: {data.get('target', 'unknown')}
TRÁFICO ACTUAL: {data.get('current_gbps', 0)} Gbps | BASELINE: {data.get('baseline_gbps', 0)} Gbps
PAQUETES/SEG: {data.get('pps', 0)}
CONEXIONES ACTIVAS: {data.get('active_connections', 0)}

DISTRIBUCIÓN DE TRÁFICO:
{json.dumps(data.get('traffic_distribution', {}), indent=2, default=str)[:1500]}

TOP IPs ATACANTES:
{json.dumps(data.get('top_source_ips', [])[:20], indent=2, default=str)[:1000]}

LATENCIA ACTUAL: {data.get('latency_ms', 0)} ms
PACKET LOSS: {data.get('packet_loss_pct', 0)}%

Determina el tipo de ataque y propone mitigaciones inmediatas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "attack_type": "unknown", "mitigation_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", f"DDoS Detectado: {result.get('attack_type', '')}"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.DDOS,
                confidence=a.get("confidence", 0.92),
                affected_assets=[data.get("target", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ip in result.get("source_ips", [])[:20]:
            if ip:
                iocs.append(IOC(type=IOCType.IP, value=str(ip), confidence=0.75, source=self.name, tags=["ddos"]))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"type": result.get("attack_type"), "vector": result.get("attack_vector"), "gbps": result.get("traffic_gbps")}],
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.92,
            recommendations=result.get("mitigation_actions", []),
            raw_ai_response=response,
        )
