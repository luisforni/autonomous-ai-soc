"""Agente de Forense de Memoria."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class MemoryForensicsAgent(BaseAgent):
    name = "MemoryForensicsAgent"
    description = "Forense de memoria RAM — volcado, análisis con Volatility, malware en memoria"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.HIGH
    tags = ["memory", "forensics", "volatility", "ram", "process-injection"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Forense de Memoria del AI-SOC. Analizas volcados de memoria con Volatility:

Análisis de memoria:
- Listado de procesos (pslist, pstree, psscan): procesos ocultos
- Conexiones de red en memoria (netscan, netstat)
- DLLs y módulos cargados (dlllist, modules)
- Inyección de código (malfind): memoria ejecutable no respaldada
- Credenciales en memoria (hashdump, cachedump, lsadump)
- Strings maliciosas en memoria de procesos
- Shellcode y exploits en memoria

Responde en JSON: risk_score, memory_profile, malicious_processes, injected_code, credentials_found, iocs, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el volcado de memoria:

SISTEMA: {data.get('hostname', 'unknown')}
PERFIL: {data.get('memory_profile', 'Win10x64')}
TAMAÑO: {data.get('dump_size_gb', 0)} GB

SALIDA DE VOLATILITY:
{json.dumps(data.get('volatility_output', {}), indent=2, default=str)[:4000]}

PROCESOS SOSPECHOSOS PRE-IDENTIFICADOS:
{json.dumps(data.get('suspicious_processes', [])[:15], indent=2, default=str)[:1000]}

Detecta malware en memoria y extrae IOCs."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "malicious_processes": [], "iocs": [], "alerts": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Malware en Memoria"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.MALWARE,
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("hostname", "unknown")],
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
            findings=result.get("malicious_processes", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
