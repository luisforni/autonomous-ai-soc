"""Agente Helm Chart Analyzer."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class HelmChartAnalyzerAgent(BaseAgent):
    name = "HelmChartAnalyzerAgent"
    description = "Análisis de seguridad en Helm Charts — misconfiguraciones, secretos, defaults inseguros"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.MEDIUM
    tags = ["helm", "kubernetes", "charts", "iac", "security"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Helm Charts del AI-SOC. Detectas en charts Helm:
- Valores por defecto inseguros (admin/admin, password vacío)
- Secretos en values.yaml en texto plano
- Templates sin security context
- RBAC con permisos excesivos en templates
- Resources sin limits definidos
- Imágenes usando :latest tag
- Ingress sin TLS configurado
- Charts de terceros con vulnerabilidades

Responde en JSON: risk_score, chart_findings, insecure_defaults, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza el Helm Chart:

CHART: {data.get('chart_name', 'unknown')} v{data.get('chart_version', 'unknown')}
REPOSITORIO: {data.get('repo', 'unknown')}

VALUES:
{json.dumps(data.get('values', {}), indent=2, default=str)[:2000]}

TEMPLATES (muestra):
{str(data.get('templates_sample', ''))[:1000]}

Detecta configuraciones inseguras y defaults problemáticos."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "chart_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Chart Helm Inseguro"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.8),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("chart_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.8,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
