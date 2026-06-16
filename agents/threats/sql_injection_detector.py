"""Agente Detector de SQL Injection."""

from __future__ import annotations

import json
import re
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class SQLInjectionDetectorAgent(BaseAgent):
    name = "SQLInjectionDetectorAgent"
    description = "Detección de SQL Injection — error-based, blind, time-based, out-of-band"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.HIGH
    tags = ["sqli", "injection", "owasp", "database", "web"]

    SQLI_PATTERNS = [
        r"'(?: |%20)*(?:or|and|union|select|insert|delete|drop|update|exec)",
        r"(?:union|select|insert|delete|update|drop|create|alter|exec|execute)\s",
        r"(?:--|#|\/\*)",
        r"(?:1=1|1 = 1|'='|\"=\")",
        r"(?:xp_cmdshell|sp_execute|sp_executesql|exec\()",
        r"(?:sleep\(|benchmark\(|waitfor delay)",
        r"(?:information_schema|sys\.tables|all_tables)",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de SQL Injection del AI-SOC. Detectas OWASP A03:2021:
- Error-based SQLi: extracción de datos mediante errores
- Union-based SQLi: uso de UNION para obtener datos
- Blind SQLi: boolean-based y time-based
- Out-of-band SQLi: DNS/HTTP exfiltración
- Second-order SQLi: payload almacenado que se ejecuta después
- Stacked queries

Responde en JSON: risk_score, sqli_type, payload_examples, affected_parameters, database_type, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        pre_detected = self._pre_detect(data.get("requests", []))
        return f"""Analiza las siguientes peticiones en busca de SQL Injection:

APLICACIÓN: {data.get('application', 'unknown')}
DB BACKEND: {data.get('db_type', 'unknown')}

PETICIONES HTTP:
{json.dumps(data.get('requests', [])[:50], indent=2, default=str)[:3000]}

PRE-DETECCIÓN (regex): {len(pre_detected)} patrones detectados
PAYLOADS SOSPECHOSOS: {pre_detected[:5]}

RESPUESTAS CON ERRORES DB: {data.get('db_errors', [])}

Confirma si hay SQLi, el tipo y el impacto potencial."""

    def _pre_detect(self, requests: list) -> list[str]:
        found = []
        for req in requests:
            raw = json.dumps(req)
            for pattern in self.SQLI_PATTERNS:
                if re.search(pattern, raw, re.IGNORECASE):
                    found.append(raw[:100])
                    break
        return found[:10]

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "sqli_type": "none", "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", f"SQL Injection: {result.get('sqli_type', '')}"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL if self._parse_score(result.get("risk_score")) >= 8 else Severity.HIGH,
                category=ThreatCategory.INJECTION,
                confidence=a.get("confidence", 0.9),
                affected_assets=[data.get("application", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("payload_examples", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
