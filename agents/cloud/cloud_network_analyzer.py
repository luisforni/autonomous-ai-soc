"""Agente Cloud Network Analyzer."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, Severity, ThreatCategory


class CloudNetworkAnalyzerAgent(BaseCloudAgent):
    name = "CloudNetworkAnalyzerAgent"
    description = "Análisis de redes cloud — VPC, NSG, security groups, flow logs"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "multi-cloud"
    tags = ["network", "vpc", "nsg", "security-groups", "flow-logs"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Redes Cloud del AI-SOC. Analizas configuraciones de red cloud:
- Security Groups/NSGs con 0.0.0.0/0 en puertos críticos (22, 3389, 3306, 5432)
- VPCs sin segmentación adecuada
- Flow logs deshabilitados
- Peering connections no autorizadas
- Internet Gateways sin justificación
- NACLs permisivas
- VPN/Direct Connect configuración
- Tráfico de red anómalo en flow logs

Responde en JSON: risk_score, network_findings, open_ports, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la configuración de red cloud:

PROVEEDOR: {data.get('provider', 'AWS')}
CUENTA: {data.get('account', 'unknown')}

SECURITY GROUPS/NSGs:
{json.dumps(data.get('security_groups', [])[:20], indent=2, default=str)[:2000]}

VPCs/vNETs:
{json.dumps(data.get('networks', [])[:10], indent=2, default=str)[:1000]}

FLOW LOGS (muestra):
{json.dumps(data.get('flow_logs', [])[:30], indent=2, default=str)[:1500]}

Detecta configuraciones de red inseguras y tráfico anómalo."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "network_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo de Red Cloud"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.85),
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
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
