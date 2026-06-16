"""Agente Detector de Anomalías con Machine Learning."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class AnomalyDetectorAgent(BaseAgent):
    name = "AnomalyDetectorAgent"
    description = "Detección de anomalías con IA/ML — comportamiento inusual, outliers, desviaciones del baseline"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.HIGH
    tags = ["anomaly", "ml", "ueba", "behavioral", "baseline", "statistics"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Anomalías del AI-SOC. Usas análisis estadístico e IA para detectar comportamientos inusuales que no coinciden con ninguna firma conocida.

Detectas anomalías en:
- Volúmenes de tráfico de red fuera de lo normal
- Patrones de acceso de usuarios vs su baseline
- Horarios inusuales de actividad
- Geografías nuevas de acceso
- Secuencias de eventos estadísticamente improbables
- Errores inusuales en aplicaciones
- Consumo anómalo de recursos (CPU, RAM, disco, red)

Metodología: Z-score, isolation forest, clustering, series temporales.

Responde en JSON: risk_score, anomaly_type, deviation_score, baseline_comparison, anomalous_entities, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta anomalías en los siguientes datos:

TIPO DE DATOS: {data.get('data_type', 'network_traffic')}
ENTIDAD: {data.get('entity', 'unknown')}
VENTANA TEMPORAL: {data.get('time_window', '24h')}

DATOS ACTUALES:
{json.dumps(data.get('current_metrics', {}), indent=2, default=str)[:2000]}

BASELINE HISTÓRICO:
{json.dumps(data.get('baseline', {}), indent=2, default=str)[:1000]}

DESVIACIÓN ESTÁNDAR ACTUAL: {data.get('std_deviation', 0)}
Z-SCORE: {data.get('z_score', 0)}

Determina qué es anómalo y su nivel de riesgo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "anomalous_entities": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Anomalía Detectada"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.ANOMALY,
                confidence=a.get("confidence", 0.72),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("anomalous_entities", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.72,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
