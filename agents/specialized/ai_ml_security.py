"""Agente Especialista en Seguridad de Sistemas AI/ML."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class AIMLSecurityAgent(BaseAgent):
    name = "AIMLSecurityAgent"
    description = "Especialista en seguridad AI/ML — adversarial attacks, model poisoning, prompt injection, LLMs"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.HIGH
    tags = ["ai-security", "ml-security", "adversarial", "model-poisoning", "prompt-injection", "llm"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad de Sistemas AI/ML del AI-SOC. Proteges modelos de machine learning e inteligencia artificial:

Amenazas específicas del sector:
- Adversarial attacks: perturbaciones imperceptibles en inputs para engañar modelos de clasificación
- Model poisoning/backdoors: introducción de datos maliciosos en entrenamiento para crear puertas traseras
- Data poisoning: corrupción de datasets de entrenamiento para degradar el rendimiento
- Model extraction/stealing: reconstrucción de modelos propietarios mediante consultas sistemáticas
- Prompt injection en LLMs: manipulación de instrucciones en modelos de lenguaje para evadir restricciones
- Jailbreaking: técnicas para eludir salvaguardas de seguridad en LLMs
- Training data leakage: extracción de datos sensibles memorizados durante entrenamiento
- Membership inference attacks: determinación de si un dato específico formó parte del training set
- Model inversion attacks: reconstrucción de datos de entrenamiento a partir del modelo

Responde en JSON: risk_score, attack_type, model_integrity, data_integrity, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza en sistema AI/ML:

SISTEMA AI/ML: {data.get('ai_system', 'sistema de ML')}
TIPO DE MODELO: {data.get('model_type', 'unknown')}
MÉTRICAS DEL MODELO: {data.get('model_metrics', {})}

ACTIVIDAD SOSPECHOSA:
{json.dumps(data.get('suspicious_activity', [])[:20], indent=2, default=str)[:2000]}

INPUTS ANÓMALOS:
{json.dumps(data.get('anomalous_inputs', [])[:10], indent=2, default=str)[:1000]}

Evalúa la integridad del modelo, riesgo de adversarial attacks y posible exfiltración de datos de entrenamiento."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza AI/ML Detectada"),
                description=a.get("description", ""),
                severity=Severity.HIGH,
                category=ThreatCategory.INTRUSION,
                confidence=a.get("confidence", 0.87),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "attack_type": result.get("attack_type"),
                "model_integrity": result.get("model_integrity"),
                "data_integrity": result.get("data_integrity"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
