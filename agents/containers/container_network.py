"""Agente Container Network Analyzer."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ContainerNetworkAnalyzerAgent(BaseAgent):
    name = "ContainerNetworkAnalyzerAgent"
    description = "Análisis de redes de contenedores — network policies, CNI, tráfico entre pods"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.MEDIUM
    tags = ["kubernetes", "docker", "network", "cni", "network-policy"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Redes de Contenedores del AI-SOC. Detectas:
- Namespaces sin NetworkPolicy (comunicación libre entre todos los pods)
- Pods con hostNetwork: true
- Servicios NodePort/LoadBalancer expuestos innecesariamente
- CNI con vulnerabilidades conocidas
- Tráfico lateral entre namespaces no autorizado
- Ingress controllers mal configurados
- Service mesh sin mTLS

Responde en JSON: risk_score, network_findings, exposed_services, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las redes del entorno de contenedores:

CLUSTER: {data.get('cluster', 'unknown')}
CNI: {data.get('cni', 'unknown')}

NETWORK POLICIES:
{json.dumps(data.get('network_policies', [])[:15], indent=2, default=str)[:1500]}

SERVICIOS EXPUESTOS:
{json.dumps(data.get('services', [])[:20], indent=2, default=str)[:1500]}

NAMESPACES SIN POLICY: {data.get('unprotected_namespaces', [])}

Detecta comunicaciones inseguras entre contenedores."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "network_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Red Insegura de Contenedores"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.LATERAL_MOVEMENT,
                confidence=a.get("confidence", 0.82),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("network_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
