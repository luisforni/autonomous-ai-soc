"""Agente UEBA — User and Entity Behavior Analytics."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class UEBAAnalyzerAgent(BaseAgent):
    name = "UEBAAnalyzerAgent"
    description = "Análisis de comportamiento de usuarios y entidades para detectar anomalías internas"
    version = "1.0.0"
    category = "analytics"
    priority = AgentPriority.HIGH
    tags = ["ueba", "behavior", "insider", "anomaly", "baseline", "user-analytics"]

    RISK_BEHAVIORS = [
        "acceso fuera de horario habitual",
        "descarga masiva de datos",
        "acceso a recursos no habituales",
        "múltiples fallos de autenticación",
        "escalada de privilegios inusual",
        "uso de herramientas de administración desde cuenta estándar",
        "acceso a datos sensibles de clientes",
        "envío de datos a destinos externos",
        "cambio de patrones de trabajo",
        "acceso desde múltiples ubicaciones geográficas simultáneas",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador UEBA (User and Entity Behavior Analytics) del AI-SOC.

Tu especialidad es detectar amenazas internas y comportamientos anómalos mediante análisis estadístico y de IA:

1. **Baseline de comportamiento**: Estableces la línea base de cada usuario/entidad
2. **Detección de desviaciones**: Identificas cuando el comportamiento se aleja de la norma
3. **Risk Scoring dinámico**: Calculás un score de riesgo actualizado en tiempo real
4. **Correlación temporal**: Analizas patrones a lo largo del tiempo
5. **Peer group analysis**: Comparás con usuarios similares

Categorías de riesgo que evalúas:
- Exfiltración de datos (acceso + descarga + movimiento)
- Compromiso de cuenta (credenciales robadas, movimiento lateral)
- Amenaza interna maliciosa (empleado descontento, sabotaje)
- Amenaza interna accidental (negligencia, error)
- Compromiso de entidad (servidor, aplicación comprometida)

Responde en JSON:
{
  "risk_score": float (0-10),
  "risk_level": "critical|high|medium|low|info",
  "user_id": str,
  "behavior_deviations": [{"behavior": str, "baseline": str, "observed": str, "deviation_score": float}],
  "risk_factors": [str],
  "threat_category": str,
  "confidence": float,
  "alerts": [{"title": str, "description": str, "severity": str, "evidence": [str]}],
  "iocs": [{"type": str, "value": str}],
  "recommendations": [str],
  "investigation_steps": [str]
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el comportamiento de usuario/entidad para detectar anomalías:

USUARIO/ENTIDAD: {data.get('user_id', 'unknown')} | ROL: {data.get('role', 'unknown')} | DEPARTAMENTO: {data.get('department', 'unknown')}
SECTOR CLIENTE: {data.get('sector', 'enterprise')}

ACTIVIDAD RECIENTE (últimas {data.get('time_window', '24h')}):
{json.dumps(data.get('activities', [])[:30], indent=2, default=str)[:3000]}

BASELINE DEL USUARIO:
- Horario habitual: {data.get('baseline_hours', '9:00-18:00')}
- Volumen diario de datos: {data.get('baseline_data_volume', '500MB')}
- Recursos habituales: {data.get('baseline_resources', [])}
- Ubicaciones habituales: {data.get('baseline_locations', [])}

ACTIVIDAD ACTUAL:
- Horario de acceso: {data.get('current_hours', 'desconocido')}
- Volumen de datos: {data.get('current_data_volume', 'desconocido')}
- Recursos accedidos: {data.get('current_resources', [])}
- Ubicaciones: {data.get('current_locations', [])}

ALERTAS PREVIAS DEL USUARIO: {data.get('previous_alerts', 0)}
SCORE DE RIESGO ANTERIOR: {data.get('previous_risk_score', 0)}

COMPORTAMIENTOS DE RIESGO CONOCIDOS: {self.RISK_BEHAVIORS[:8]}

Determina el nivel de riesgo, las desviaciones del comportamiento normal y las acciones recomendadas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        risk_score = self._parse_score(result.get("risk_score"))

        if risk_score >= 7:
            alerts.append(self._create_alert(
                title=f"Comportamiento Anómalo Crítico: {data.get('user_id', 'unknown')}",
                description=f"UEBA detectó comportamiento de alto riesgo. Score: {risk_score:.1f}/10. Factores: {', '.join(result.get('risk_factors', [])[:3])}",
                severity=Severity.CRITICAL if risk_score >= 9 else Severity.HIGH,
                category=ThreatCategory.INSIDER_THREAT,
                confidence=self._parse_score(result.get("confidence"), 0.85),
                recommendations=result.get("recommendations", []),
            ))
        elif risk_score >= 4:
            alerts.append(self._create_alert(
                title=f"Anomalía de Comportamiento: {data.get('user_id', 'unknown')}",
                description=f"Desviación del comportamiento normal detectada. Score: {risk_score:.1f}/10",
                severity=Severity.MEDIUM,
                category=ThreatCategory.ANOMALY,
                confidence=self._parse_score(result.get("confidence"), 0.7),
                recommendations=result.get("recommendations", []),
            ))

        for alert_data in result.get("alerts", []):
            alerts.append(self._create_alert(
                title=alert_data.get("title", "Anomalía UEBA"),
                description=alert_data.get("description", ""),
                severity=Severity(alert_data.get("severity", "medium")),
                category=ThreatCategory.INSIDER_THREAT,
                confidence=0.8,
            ))

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(
                    type=IOCType(ioc_data["type"]),
                    value=ioc_data["value"],
                    source=self.name,
                    tags=["ueba", "behavioral"],
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("behavior_deviations", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=risk_score,
            confidence=self._parse_score(result.get("confidence"), 0.8),
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
