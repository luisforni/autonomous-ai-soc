"""Agente RBAC Kubernetes."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class KubernetesRBACAnalyzerAgent(BaseAgent):
    name = "KubernetesRBACAnalyzerAgent"
    description = "Análisis de RBAC en Kubernetes — roles, bindings, service accounts, permisos excesivos"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.HIGH
    tags = ["kubernetes", "rbac", "permissions", "service-accounts", "least-privilege"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador RBAC de Kubernetes del AI-SOC. Detectas:
- ClusterRoles con wildcards (* en resources, verbs, apiGroups)
- Service accounts con ClusterAdmin o permisos excesivos
- Bindings que dan acceso a namespaces sensibles (kube-system)
- Service accounts montadas automáticamente sin necesidad
- Roles que permiten crear/modificar ClusterRoles (privilege escalation)
- Usuarios anónimos con permisos
- Impersonation permissions

Responde en JSON: risk_score, rbac_analysis, privilege_escalation_paths, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el RBAC de Kubernetes:

CLUSTER: {data.get('cluster_name', 'unknown')}

CLUSTERROLES:
{json.dumps(data.get('cluster_roles', [])[:20], indent=2, default=str)[:2000]}

ROLEBINDINGS:
{json.dumps(data.get('role_bindings', [])[:20], indent=2, default=str)[:2000]}

SERVICE ACCOUNTS:
{json.dumps(data.get('service_accounts', [])[:20], indent=2, default=str)[:1000]}

Detecta paths de escalada de privilegios y permisos excesivos."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "privilege_escalation_paths": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "RBAC K8s Inseguro"),
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
            findings=result.get("privilege_escalation_paths", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
