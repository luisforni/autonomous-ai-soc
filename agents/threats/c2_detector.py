"""Agente Detector de Command & Control (C2)."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class C2DetectorAgent(BaseAgent):
    name = "C2DetectorAgent"
    description = "Detección de comunicaciones Command & Control — beaconing, C2 frameworks"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["c2", "command-control", "beaconing", "cobalt-strike", "metasploit"]

    C2_FRAMEWORKS = [
        "Cobalt Strike", "Metasploit", "PowerShell Empire", "Covenant",
        "Sliver", "Brute Ratel", "Havoc", "Mythic", "PoshC2", "Merlin",
    ]

    def _build_system_prompt(self) -> str:
        return f"""Eres el Detector de C2 del AI-SOC. Detectas comunicaciones con servidores de comando y control:

Técnicas de C2:
- Beaconing: conexiones periódicas a intervalos regulares (jitter incluido)
- HTTP/HTTPS C2: Cobalt Strike malleable profiles, Metasploit handlers
- DNS C2: queries a subdominios generados dinámicamente
- Domain Fronting: uso de CDNs para ocultar C2
- FastFlux: cambio rápido de IPs en DNS
- P2P C2: comunicación peer-to-peer entre infectados
- Social media C2: Twitter, GitHub, Pastebin como canales

Frameworks conocidos: {self.C2_FRAMEWORKS}

Responde en JSON: risk_score, c2_framework, beacon_interval_seconds, c2_server, communication_pattern, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta comunicaciones C2:

HOST SOSPECHOSO: {data.get('hostname', 'unknown')}

CONEXIONES DE RED (24h):
{json.dumps(data.get('connections', [])[:50], indent=2, default=str)[:3000]}

PATRONES TEMPORALES DE CONEXIÓN:
{json.dumps(data.get('connection_times', [])[:50], indent=2, default=str)[:1000]}

DOMINIOS CONTACTADOS:
{json.dumps(data.get('domains', [])[:30], indent=2, default=str)[:1000]}

PROCESO INICIANDO CONEXIONES: {data.get('process', 'unknown')}
USER AGENT: {data.get('user_agent', 'unknown')}

Detecta beaconing y comunicaciones C2 ocultas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "c2_server": "unknown", "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", f"C2 Detectado: {result.get('c2_framework', 'Desconocido')}"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.C2,
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        if result.get("c2_server"):
            iocs.append(IOC(type=IOCType.IP, value=str(result["c2_server"]), confidence=0.85, source=self.name, tags=["c2"]))

        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"framework": result.get("c2_framework"), "interval": result.get("beacon_interval_seconds"), "pattern": result.get("communication_pattern")}],
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
