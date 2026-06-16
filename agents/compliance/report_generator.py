"""Agente Generador de Reportes."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis


class ReportGeneratorAgent(BaseAgent):
    name = "ReportGeneratorAgent"
    description = "Generación automática de reportes de seguridad — ejecutivos, técnicos, regulatorios"
    version = "1.0.0"
    category = "compliance"
    priority = AgentPriority.LOW
    tags = ["reporting", "executive", "technical", "regulatory", "dashboard"]

    def _build_system_prompt(self) -> str:
        return """Eres el Generador de Reportes del AI-SOC. Produces reportes profesionales:

Tipos de reporte:
- Ejecutivo: métricas de alto nivel, riesgo, ROI en seguridad (no técnico)
- Técnico: detalle de vulnerabilidades, IOCs, análisis forense
- Semanal/Mensual: resumen de incidentes, tendencias, KPIs
- Regulatorio: formato específico para GDPR, PCI-DSS, HIPAA
- Incidente: reporte completo de un incidente específico
- Threat Intelligence: amenazas actuales relevantes para el sector

Formato: estructurado, claro, con datos y recomendaciones accionables.

Responde en JSON: report_type, executive_summary, key_findings, metrics, trends, recommendations, risk_rating."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Genera el reporte de seguridad:

TIPO: {data.get('report_type', 'monthly')}
PERIODO: {data.get('period', 'último mes')}
AUDIENCIA: {data.get('audience', 'executive')}
CLIENTE: {data.get('client', 'unknown')}

DATOS PARA EL REPORTE:
{json.dumps(data.get('report_data', {}), indent=2, default=str)[:4000]}

MÉTRICAS CLAVE: {data.get('key_metrics', {})}
INCIDENTES DEL PERIODO: {data.get('incidents', [])}

Genera el reporte en el formato apropiado para la audiencia."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"executive_summary": "", "key_findings": [], "recommendations": []})

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("key_findings", []),
            alerts=[],
            iocs=[],
            risk_score=self._parse_score(result.get("risk_rating")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
