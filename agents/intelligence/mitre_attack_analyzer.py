"""Agente Analizador MITRE ATT&CK."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class MITREATTACKAnalyzerAgent(BaseAgent):
    name = "MITREATTACKAnalyzerAgent"
    description = "Mapeo con MITRE ATT&CK — tácticas, técnicas, sub-técnicas, detección y mitigación"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.HIGH
    tags = ["mitre", "attack", "ttps", "tactics", "techniques", "d3fend"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador MITRE ATT&CK del AI-SOC. Para cualquier actividad sospechosa:

1. Mapeas con MITRE ATT&CK Enterprise/Cloud/Mobile
2. Identificas las tácticas (TA00XX) y técnicas (TXXXX) específicas
3. Determinas sub-técnicas cuando aplica (T1XXX.XXX)
4. Correlacionas con procedimientos de actores conocidos
5. Propones detecciones específicas (data sources, analytics)
6. Mapeas con MITRE D3FEND para defensas

Responde en JSON: risk_score, tactics, techniques, sub_techniques, actor_procedures, detection_opportunities, mitigations, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Mapea la siguiente actividad con MITRE ATT&CK:

ACTIVIDADES OBSERVADAS:
{json.dumps(data.get('activities', [])[:20], indent=2, default=str)[:2000]}

HERRAMIENTAS DETECTADAS: {data.get('tools', [])}
SISTEMA OPERATIVO: {data.get('os', 'Windows')}
ENTORNO: {data.get('environment', 'enterprise')}

Genera el mapping completo con ATT&CK y las defensas recomendadas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "tactics": [], "techniques": [], "alerts": [], "mitigations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Técnica ATT&CK Detectada"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.APT,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("techniques", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("mitigations", []),
            raw_ai_response=response,
        )
