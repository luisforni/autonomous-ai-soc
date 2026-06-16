"""Agente Service Mesh Analyzer."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ServiceMeshAnalyzerAgent(BaseAgent):
    name = "ServiceMeshAnalyzerAgent"
    description = "Análisis de service mesh (Istio, Linkerd) — mTLS, políticas de autorización"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.MEDIUM
    tags = ["istio", "linkerd", "service-mesh", "mtls", "zero-trust"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Service Mesh del AI-SOC. Analizas Istio/Linkerd:
- mTLS habilitado en todos los namespaces
- PeerAuthentication policies en modo STRICT
- AuthorizationPolicies demasiado permisivas
- Egress traffic no controlado
- Certificate rotation configurada
- Telemetría y tracing habilitados
- Control plane expuesto
- Envoy proxy desactualizado

Responde en JSON: risk_score, mesh_type, security_findings, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el service mesh:

TIPO: {data.get('mesh_type', 'Istio')}
VERSIÓN: {data.get('mesh_version', 'unknown')}
CLUSTER: {data.get('cluster', 'unknown')}

PEER AUTHENTICATIONS:
{json.dumps(data.get('peer_auth', [])[:10], indent=2, default=str)[:1000]}

AUTHORIZATION POLICIES:
{json.dumps(data.get('auth_policies', [])[:10], indent=2, default=str)[:1000]}

NAMESPACES SIN mTLS: {data.get('plaintext_namespaces', [])}

Detecta configuraciones inseguras del service mesh."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "security_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Service Mesh Inseguro"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.82),
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
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
