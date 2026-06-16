"""Agente Pod Security Analyzer."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class PodSecurityAnalyzerAgent(BaseAgent):
    name = "PodSecurityAnalyzerAgent"
    description = "Análisis de seguridad de pods — security context, capabilities, volumes"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.HIGH
    tags = ["kubernetes", "pods", "security-context", "psa", "capabilities"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Seguridad de Pods del AI-SOC. Evalúas pods según:
- privileged: true sin justificación
- runAsRoot o runAsNonRoot: false
- allowPrivilegeEscalation: true
- Capabilities adicionales (NET_ADMIN, SYS_ADMIN, etc.)
- hostPID, hostIPC, hostNetwork: true
- hostPath volumes montando /etc, /var/run/docker.sock
- Recursos sin limits (CPU/memory)
- Liveness/Readiness probes mal configuradas
- Seccompprofile no definido

Responde en JSON: risk_score, pod_findings, high_risk_pods, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad de los pods:

NAMESPACE: {data.get('namespace', 'default')}
CLUSTER: {data.get('cluster', 'unknown')}

PODS:
{json.dumps(data.get('pods', [])[:30], indent=2, default=str)[:4000]}

Detecta pods con configuraciones inseguras."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "high_risk_pods": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Pod Inseguro"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                confidence=a.get("confidence", 0.87),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("high_risk_pods", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
