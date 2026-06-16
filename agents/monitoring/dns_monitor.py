"""Agente Monitor DNS — detección de DNS tunneling, DGA y dominios maliciosos."""

from __future__ import annotations

import json
import re
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class DNSMonitorAgent(BaseAgent):
    name = "DNSMonitorAgent"
    description = "Monitoreo DNS: tunneling, DGA, fast-flux, dominios maliciosos"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["dns", "dga", "tunneling", "domain", "monitoring"]

    SUSPICIOUS_PATTERNS = [
        r"\.ru$", r"\.cn$", r"\.tk$", r"\.pw$", r"\.cc$",
        r"[a-z0-9]{30,}\.",
        r"\d{4,}\.",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente Monitor DNS del AI-SOC. Analizas consultas DNS para detectar:
- DNS tunneling (exfiltración de datos vía DNS)
- Dominios generados por algoritmos (DGA) usados por malware
- Fast-flux y técnicas de evasión DNS
- Consultas a dominios de C2 conocidos
- Typosquatting y phishing de dominios
- Resoluciones hacia IPs maliciosas

Responde en JSON: risk_score, dns_stats, suspicious_domains, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza las siguientes consultas DNS:

CONSULTAS DNS:
{json.dumps(data.get('queries', [])[:200], indent=2, default=str)}

RESOLUCIONES:
{json.dumps(data.get('resolutions', {}), indent=2, default=str)[:2000]}

DOMINIOS SOSPECHOSOS PRE-DETECTADOS: {self._check_suspicious(data.get('queries', []))}

Detecta tunneling DNS, DGA y dominios maliciosos."""

    def _check_suspicious(self, queries: list) -> list[str]:
        suspicious = []
        for q in queries:
            domain = q if isinstance(q, str) else q.get("domain", "")
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, domain):
                    suspicious.append(domain)
                    break
        return list(set(suspicious))[:20]

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Alerta DNS"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.C2 if "tunnel" in a.get("title", "").lower() else ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.7),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        for domain in result.get("suspicious_domains", []):
            iocs.append(IOC(type=IOCType.DOMAIN, value=str(domain), confidence=0.6, source=self.name))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("suspicious_domains", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
