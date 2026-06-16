"""Agente Detector de Ataques a la Cadena de Suministro."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class SupplyChainAttackDetectorAgent(BaseAgent):
    name = "SupplyChainAttackDetectorAgent"
    description = "Detección de ataques a la cadena de suministro — software, npm, PyPI, SolarWinds-like"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["supply-chain", "solarwinds", "npm", "pypi", "dependency", "typosquatting"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Ataques de Supply Chain del AI-SOC. Detectas compromisos en la cadena de suministro:

Vectores de ataque:
- Typosquatting en npm, PyPI, Maven (paquetes con nombres similares)
- Dependency confusion (paquetes internos suplantados en repos públicos)
- Paquetes legítimos comprometidos (SolarWinds-like)
- Build system compromise (CI/CD envenenado)
- Source code repository compromise
- Firmware malicioso en hardware
- Updates maliciosas de software legítimo

Responde en JSON: risk_score, attack_vector, compromised_package, affected_systems, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta posible ataque a la cadena de suministro:

TIPO: {data.get('type', 'software')}

PAQUETES/DEPENDENCIAS:
{json.dumps(data.get('packages', [])[:30], indent=2, default=str)[:2000]}

ACTUALIZACIONES RECIENTES:
{json.dumps(data.get('recent_updates', [])[:20], indent=2, default=str)[:1000]}

COMPORTAMIENTO POST-INSTALACIÓN:
{json.dumps(data.get('post_install_behavior', [])[:10], indent=2, default=str)[:500]}

HASHES ESPERADOS vs REALES:
{json.dumps(data.get('hash_comparison', [])[:10], indent=2, default=str)[:500]}

Determina si hay un compromiso de cadena de suministro."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "compromised_package": "unknown", "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Ataque Supply Chain Detectado"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.SUPPLY_CHAIN,
                confidence=a.get("confidence", 0.82),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"package": result.get("compromised_package"), "vector": result.get("attack_vector")}],
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
