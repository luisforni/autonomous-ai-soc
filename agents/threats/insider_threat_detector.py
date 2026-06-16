"""Agente Detector de Amenazas Internas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class InsiderThreatDetectorAgent(BaseAgent):
    name = "InsiderThreatDetectorAgent"
    description = "Detección de amenazas internas — empleados maliciosos, negligencia, cuenta comprometida"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.HIGH
    tags = ["insider-threat", "ueba", "dlp", "behavioral", "user-monitoring"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Amenazas Internas del AI-SOC. Detectas comportamientos sospechosos de empleados:

Indicadores de amenaza interna maliciosa:
- Descarga masiva de datos antes de renuncia/despido
- Acceso a sistemas fuera de su área de trabajo
- Uso de dispositivos USB no autorizados
- Envío de datos a email personal
- Acceso fuera de horario laboral
- Búsquedas de datos de competidores
- Escalada de privilegios no solicitada

Indicadores de cuenta comprometida:
- Login desde ubicación geográfica inusual
- Múltiples sesiones simultáneas en países diferentes
- Comportamiento muy diferente al baseline histórico

NOTA: Respeta privacidad — no generes alertas sin evidencia suficiente.

Responde en JSON: risk_score, threat_type, risk_indicators, behavioral_anomalies, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el comportamiento del usuario para detectar amenaza interna:

USUARIO: {data.get('username', 'unknown')}
DEPARTAMENTO: {data.get('department', 'unknown')}
ANTIGÜEDAD: {data.get('tenure_days', 0)} días
ESTADO RR.HH.: {data.get('hr_status', 'activo')}

ACTIVIDAD RECIENTE:
{json.dumps(data.get('recent_activity', [])[:30], indent=2, default=str)[:2000]}

BASELINE HISTÓRICO:
{json.dumps(data.get('historical_baseline', {}), default=str)[:500]}

ALERTAS PREVIAS: {data.get('previous_alerts', 0)}
DATOS ACCEDIDOS: {data.get('sensitive_data_accessed', [])}
DISPOSITIVOS USB: {data.get('usb_usage', False)}

Evalúa el riesgo de amenaza interna con evidencias concretas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "behavioral_anomalies": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Posible Amenaza Interna"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.INSIDER_THREAT,
                confidence=a.get("confidence", 0.7),
                affected_assets=[data.get("username", "unknown")],
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
            confidence=0.7,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
