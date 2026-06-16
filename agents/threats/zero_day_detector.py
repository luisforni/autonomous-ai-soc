"""Agente Detector de Zero-Day."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ZeroDayDetectorAgent(BaseAgent):
    name = "ZeroDayDetectorAgent"
    description = "Detección de exploits zero-day mediante análisis heurístico y comportamental"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["zero-day", "exploit", "0day", "heuristic", "behavioral"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Zero-Day del AI-SOC. Detectas exploits desconocidos mediante:

Señales de zero-day:
- Crash de aplicaciones con patterns específicos
- Shellcode execution en memoria (NX/DEP bypass)
- Return-oriented programming (ROP chains) en memoria
- Heap spray patterns
- Comportamiento anómalo de aplicaciones sin firma de malware conocida
- ASLR/Stack cookie bypass en aplicaciones
- Comportamiento de proceso que no coincide con la firma digital
- Explotación de servicios con vulnerabilidades sin CVE conocido

Responde en JSON: risk_score, exploit_type, target_application, indicators, behavioral_anomalies, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza en busca de posible zero-day:

APLICACIÓN: {data.get('application', 'unknown')} v{data.get('version', 'unknown')}
SISTEMA: {data.get('os', 'unknown')}

CRASHES/EXCEPTIONS:
{json.dumps(data.get('crashes', [])[:10], indent=2, default=str)[:1500]}

COMPORTAMIENTO ANÓMALO:
{json.dumps(data.get('anomalous_behavior', [])[:20], indent=2, default=str)[:2000]}

DUMP DE MEMORIA (fragmento):
{str(data.get('memory_sample', ''))[:500]}

LLAMADAS AL SISTEMA INUSUALES: {data.get('unusual_syscalls', [])}

Determina si puede ser un zero-day y qué mitigaciones aplicar."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "behavioral_anomalies": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Posible Zero-Day Detectado"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.ZERO_DAY,
                confidence=a.get("confidence", 0.65),
                affected_assets=[data.get("application", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("behavioral_anomalies", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=self._parse_score(result.get("confidence"), 0.65),
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
