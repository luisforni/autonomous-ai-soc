"""Agente de Gestión de Parches."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class PatchManagementAgent(BaseAgent):
    name = "PatchManagementAgent"
    description = "Análisis y gestión de parches de seguridad — CVEs, priorización, cumplimiento"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.MEDIUM
    tags = ["patches", "cve", "vulnerabilities", "updates", "wsus", "yum"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Gestión de Parches del AI-SOC. Analizas el estado de parches:
- CVEs críticos sin parchear y su explotabilidad activa (CISA KEV)
- Priorización basada en CVSS y explotación real en la naturaleza
- Tiempo medio de parcheo vs SLA definido
- Activos más vulnerables (mayor superficie de ataque)
- Excepciones de parches y riesgos compensatorios
- Correlación con amenazas actuales

Responde en JSON: risk_score, patch_summary, critical_cves, overdue_patches, alerts, prioritized_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el estado de parches:

SISTEMA: {data.get('hostname', 'unknown')} | {data.get('os', 'unknown')}
ÚLTIMA ACTUALIZACIÓN: {data.get('last_update', 'unknown')}

PARCHES PENDIENTES:
{json.dumps(data.get('pending_patches', [])[:50], indent=2, default=str)[:3000]}

CVEs CONOCIDOS:
{json.dumps(data.get('cves', [])[:30], indent=2, default=str)[:2000]}

SLA DE PARCHES CRÍTICOS: {data.get('critical_patch_sla', '7 días')}
EXCEPCIONES: {data.get('exceptions', [])}

Prioriza los parches por riesgo real y genera plan de acción."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "critical_cves": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Parche Crítico Pendiente"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.VULNERABILITY,
                confidence=0.95,
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("critical_cves", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.93,
            recommendations=result.get("prioritized_actions", result.get("recommendations", [])),
            raw_ai_response=response,
        )
