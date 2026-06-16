"""Agente Especialista en Seguridad Gubernamental."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class GovernmentSecurityAgent(BaseAgent):
    name = "GovernmentSecurityAgent"
    description = "Especialista en seguridad gubernamental — APT, infraestructura crítica, sistemas clasificados"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.CRITICAL
    tags = ["government", "nation-state", "critical-infrastructure", "classified", "military"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad Gubernamental del AI-SOC. Proteges entidades gubernamentales y su infraestructura crítica:

Amenazas específicas del sector:
- Espionaje estatal (APT29, APT41, Lazarus Group): robo de información clasificada
- Ataques a infraestructura crítica: energía, agua, transporte, comunicaciones
- Compromiso de sistemas clasificados: acceso no autorizado a información sensible
- Election interference: manipulación de sistemas electorales, desinformación
- Supply chain attacks a proveedores gubernamentales: contratistas comprometidos
- Insider threats con acceso privilegiado a sistemas de seguridad nacional
- Cyber warfare: operaciones ofensivas contra infraestructuras nacionales
- Robo de propiedad intelectual militar y de defensa

Cumplimiento y marcos:
- NIST SP 800-53: controles de seguridad federal
- FedRAMP: seguridad de servicios cloud gubernamentales
- FISMA: Federal Information Security Management Act
- CJIS: Criminal Justice Information Services Security Policy
- DoD STIGs: Security Technical Implementation Guides

Responde en JSON: risk_score, threat_actor, classification_level, national_security_impact, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza en entorno gubernamental:

ENTIDAD: {data.get('institution', 'agencia gubernamental')}
NIVEL DE CLASIFICACIÓN: {data.get('classification_level', 'UNCLASSIFIED')}
SISTEMAS CRÍTICOS: {data.get('critical_systems', [])}

ACTIVIDAD SOSPECHOSA:
{json.dumps(data.get('suspicious_activity', [])[:20], indent=2, default=str)[:2000]}

INDICADORES DE APT: {data.get('apt_indicators', [])}

Evalúa el riesgo para la seguridad nacional y el impacto sobre infraestructura crítica."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza Gubernamental Crítica"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.APT,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "threat_actor": result.get("threat_actor"),
                "classification_level": result.get("classification_level"),
                "national_security_impact": result.get("national_security_impact"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
