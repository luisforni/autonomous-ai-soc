"""Agente Especialista en Seguridad Bancaria."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class BankingSecurityAgent(BaseAgent):
    name = "BankingSecurityAgent"
    description = "Especialista en seguridad bancaria y fintech — fraude, PCI-DSS, SWIFT, transacciones"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.CRITICAL
    tags = ["banking", "fintech", "fraud", "pci-dss", "swift", "aml", "transactions"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad Bancaria del AI-SOC. Proteges a bancos y fintechs:

Amenazas específicas del sector:
- Fraude transaccional: transferencias no autorizadas, account takeover
- SWIFT attacks: compromiso de mensajes interbancarios (Bangladesh Bank-like)
- ATM jackpotting: ataques físicos/lógicos a cajeros automáticos
- Card skimming: clonación de tarjetas en ATMs y POS
- Insider trading: uso de información privilegiada
- Ransomware en sistemas core bancarios
- Credential stuffing en banca online
- BEC/CEO fraud: transferencias fraudulentas

Cumplimiento:
- PCI-DSS v4.0: protección de datos de tarjetas
- DORA (EU): resiliencia operacional digital
- AML/KYC: lavado de dinero
- Regulaciones del banco central

Responde en JSON: risk_score, threat_type, financial_impact_usd, affected_accounts, alerts, immediate_actions, regulatory_notifications."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza bancaria:

INSTITUCIÓN: {data.get('institution', 'banco')}
TIPO DE AMENAZA: {data.get('threat_type', 'fraud')}
SISTEMAS AFECTADOS: {data.get('systems', [])}

ACTIVIDAD FRAUDULENTA:
{json.dumps(data.get('fraud_activity', [])[:20], indent=2, default=str)[:2000]}

TRANSACCIONES SOSPECHOSAS:
{json.dumps(data.get('suspicious_transactions', [])[:20], indent=2, default=str)[:2000]}

IMPACTO FINANCIERO ESTIMADO: USD {data.get('financial_impact', 0):,}
CUENTAS AFECTADAS: {data.get('affected_accounts', 0)}

Evalúa el riesgo y genera el plan de respuesta bancaria."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": [], "regulatory_notifications": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza Bancaria Crítica"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"financial_impact": result.get("financial_impact_usd"), "accounts": result.get("affected_accounts")}],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
