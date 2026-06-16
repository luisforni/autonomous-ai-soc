"""Agente de Reputación de IPs."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class IPReputationAgent(BaseAgent):
    name = "IPReputationAgent"
    description = "Análisis de reputación de IPs — abuse score, geolocation, ASN, blacklists"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.MEDIUM
    tags = ["ip", "reputation", "abuse", "geolocation", "asn", "blacklist"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Reputación de IPs del AI-SOC. Analizas direcciones IP:
- AbuseIPDB: score de abuso y reportes
- Shodan: puertos abiertos, servicios, vulnerabilidades
- MaxMind: geolocalización y tipo de red (datacenter, VPN, residential)
- ASN: proveedor, country, bulletproof hosting
- Listas negras: Spamhaus, SORBS, Barracuda, emergingthreats
- Historial de actividad maliciosa
- TOR exit nodes, VPN endpoints conocidos
- Rangos de IP de APTs conocidos

Responde en JSON: risk_score, ip_info, blacklist_hits, related_iocs, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la reputación de las siguientes IPs:

IPs:
{json.dumps(data.get('ips', [])[:20], indent=2, default=str)[:1000]}

CONTEXTO: {data.get('context', 'análisis de seguridad')}
DATOS DE REPUTACIÓN:
{json.dumps(data.get('reputation_data', {}), indent=2, default=str)[:2000]}

BLACKLISTS CONSULTADAS: {data.get('blacklists_checked', ['abuseipdb', 'spamhaus'])}

Determina qué IPs son maliciosas y su uso probable."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "blacklist_hits": [], "related_iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "IP Maliciosa Detectada"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.8),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ip in result.get("blacklist_hits", []):
            if isinstance(ip, dict) and ip.get("ip"):
                iocs.append(IOC(type=IOCType.IP, value=ip["ip"], confidence=float(ip.get("confidence", 0.8)), source=self.name))
            elif isinstance(ip, str):
                iocs.append(IOC(type=IOCType.IP, value=ip, confidence=0.8, source=self.name))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("blacklist_hits", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
