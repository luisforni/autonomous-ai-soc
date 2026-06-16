"""Agente Analizador de CVEs."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class CVEAnalyzerAgent(BaseAgent):
    name = "CVEAnalyzerAgent"
    description = "Análisis inteligente de CVEs — explotabilidad, impacto, PoC disponibles, priorización"
    version = "1.0.0"
    category = "intelligence"
    priority = AgentPriority.HIGH
    tags = ["cve", "vulnerability", "cvss", "exploit", "patching"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de CVEs del AI-SOC. Analizas vulnerabilidades para priorización:

Métricas evaluadas:
- CVSS v3 Base Score (NVD oficial)
- CVSS v4 cuando disponible
- EPSS score (Exploit Prediction Scoring System)
- CISA KEV (Known Exploited Vulnerabilities)
- PoC público disponible (GitHub, ExploitDB)
- Explotación activa en la naturaleza (in the wild)
- Impacto específico en el entorno del cliente
- Mitigaciones disponibles (parche, workaround, compensatorio)

Priorización: Critical = CVSS≥9 + explotación activa, High = CVSS≥7 + PoC, etc.

Responde en JSON: risk_score, cve_id, cvss_score, epss_score, exploitable_in_wild, patch_available, affected_systems, alerts, remediation_priority."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza los siguientes CVEs:

CVEs:
{json.dumps(data.get('cves', [])[:20], indent=2, default=str)[:3000]}

SISTEMAS DEL CLIENTE:
{json.dumps(data.get('affected_systems', [])[:20], indent=2, default=str)[:1000]}

SECTOR: {data.get('sector', 'unknown')}
SLA PARCHES CRÍTICOS: {data.get('critical_sla', '7 días')}

Prioriza los CVEs por riesgo real para este entorno específico."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "affected_systems": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", f"CVE Crítico: {result.get('cve_id', '')}"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL if self._parse_score(result.get("risk_score")) >= 9 else Severity.HIGH,
                category=ThreatCategory.VULNERABILITY,
                confidence=0.95,
                affected_assets=result.get("affected_systems", []),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for cve in data.get("cves", []):
            cve_id = cve if isinstance(cve, str) else cve.get("cve_id", "")
            if cve_id:
                iocs.append(IOC(type=IOCType.CVE, value=cve_id, confidence=0.9, source=self.name))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"cve": result.get("cve_id"), "cvss": result.get("cvss_score"), "exploitable": result.get("exploitable_in_wild")}],
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.93,
            recommendations=result.get("remediation_priority", []),
            raw_ai_response=response,
        )
