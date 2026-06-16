"""Agente Detector de Ingeniería Social."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class SocialEngineeringDetectorAgent(BaseAgent):
    name = "SocialEngineeringDetectorAgent"
    description = "Detección de ingeniería social — vishing, pretexting, deepfakes, SIM swapping"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.HIGH
    tags = ["social-engineering", "vishing", "pretexting", "deepfake", "sim-swap"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Ingeniería Social del AI-SOC. Detectas:
- Vishing: llamadas fraudulentas a empleados (soporte técnico, ejecutivos)
- Pretexting: escenarios falsos para extraer información
- Tailgating/piggybacking: acceso físico no autorizado
- SIM swapping: toma de control de número de teléfono
- Deepfakes de voz/video de ejecutivos
- Watering hole: sitios web comprometidos visitados por el objetivo
- Quishing: QR codes maliciosos

Responde en JSON: risk_score, technique, target, indicators, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta ingeniería social:

TIPO DE REPORTE: {data.get('report_type', 'email')}
FUENTE: {data.get('source', 'unknown')}

DESCRIPCIÓN DEL INCIDENTE:
{str(data.get('description', ''))[:2000]}

CONVERSACIONES/COMUNICACIONES:
{json.dumps(data.get('communications', [])[:10], indent=2, default=str)[:1500]}

EMPLEADO AFECTADO: {data.get('affected_employee', 'unknown')}
INFORMACIÓN SOLICITADA: {data.get('requested_info', [])}
ACCIÓN TOMADA: {data.get('action_taken', 'none')}

Evalúa si fue víctima de ingeniería social y el impacto."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "indicators": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Ingeniería Social Detectada"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.SOCIAL_ENGINEERING,
                confidence=a.get("confidence", 0.78),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("indicators", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.78,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
