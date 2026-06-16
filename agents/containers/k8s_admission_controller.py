"""Agente K8s Admission Controller."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class K8sAdmissionControllerAgent(BaseAgent):
    name = "K8sAdmissionControllerAgent"
    description = "Políticas de admisión K8s — OPA/Gatekeeper, Kyverno, validación en tiempo real"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.MEDIUM
    tags = ["kubernetes", "admission", "opa", "gatekeeper", "kyverno", "policy"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Admission Controller de K8s del AI-SOC. Analizas:
- Policies de OPA/Gatekeeper o Kyverno instaladas
- Recursos que violan las policies (violations)
- Gaps en las políticas (recursos no cubiertos)
- Webhooks de admission mal configurados (failure policy)
- Intentos de bypass de políticas
- Políticas en modo audit vs enforce
- Recursos admitidos que deberían ser rechazados

Responde en JSON: risk_score, policy_coverage, violations, policy_gaps, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las políticas de admission controller:

CLUSTER: {data.get('cluster', 'unknown')}
ADMISSION CONTROLLER: {data.get('controller_type', 'OPA/Gatekeeper')}

POLICIES INSTALADAS:
{json.dumps(data.get('policies', [])[:15], indent=2, default=str)[:1500]}

VIOLATIONS:
{json.dumps(data.get('violations', [])[:20], indent=2, default=str)[:1500]}

WEBHOOKS:
{json.dumps(data.get('webhooks', [])[:10], indent=2, default=str)[:500]}

Detecta gaps y violations críticas en las políticas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "violations": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Violation de Policy K8s"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("violations", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
