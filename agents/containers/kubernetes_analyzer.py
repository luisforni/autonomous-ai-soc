"""Agente Analizador Kubernetes."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class KubernetesAnalyzerAgent(BaseAgent):
    name = "KubernetesAnalyzerAgent"
    description = "Análisis de seguridad completo en Kubernetes — RBAC, pods, network policies, secrets"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.HIGH
    tags = ["kubernetes", "k8s", "rbac", "pods", "security", "cis"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Seguridad Kubernetes del AI-SOC. Realizas auditorías completas de K8s:

Analizas:
- RBAC: ClusterRoles excesivos, wildcards, service accounts
- Pods privilegiados y con hostPath mounts
- Network Policies: namespaces sin restricciones
- Secrets sin cifrar en etcd
- Container security context (runAsRoot, capabilities)
- Image pull de registros no confiables
- PodSecurityPolicies/PodSecurityAdmission
- API Server expuesto al exterior
- Etcd sin TLS o con acceso no autenticado
- Actividad anómala en el cluster

CIS Kubernetes Benchmark compliance.

Responde en JSON: risk_score, cluster_info, security_findings, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del cluster Kubernetes:

CLUSTER: {data.get('cluster_name', 'unknown')}
VERSIÓN K8S: {data.get('k8s_version', 'unknown')}
PROVEEDOR: {data.get('provider', 'self-managed')}

PODS CON PRIVILEGIOS:
{json.dumps(data.get('privileged_pods', [])[:20], indent=2, default=str)[:1500]}

RBAC BINDINGS:
{json.dumps(data.get('rbac', {})[:20] if isinstance(data.get('rbac'), list) else data.get('rbac', {}), indent=2, default=str)[:1500]}

NETWORK POLICIES:
{json.dumps(data.get('network_policies', [])[:10], indent=2, default=str)[:500]}

NAMESPACES: {data.get('namespaces', [])}
NODES: {data.get('node_count', 0)}
PODS TOTALES: {data.get('pod_count', 0)}

Detecta riesgos críticos en el cluster."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "security_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo Kubernetes"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("cluster_name", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("security_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
