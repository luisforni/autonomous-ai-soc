"""Agente Threat Hunter — Caza proactiva de amenazas avanzadas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class ThreatHunterAgent(BaseAgent):
    name = "ThreatHunterAgent"
    description = "Caza proactiva de amenazas avanzadas — hipótesis, búsqueda y validación"
    version = "1.0.0"
    category = "analytics"
    priority = AgentPriority.HIGH
    tags = ["threat-hunting", "proactive", "apt", "mitre", "hypothesis", "ioc-hunting"]

    HUNT_HYPOTHESES = [
        "Presencia de C2 mediante DNS tunneling",
        "Living-off-the-land attacks (LOLBins)",
        "Kerberoasting / AS-REP Roasting",
        "Pass-the-Hash / Pass-the-Ticket",
        "Golden/Silver Ticket attacks",
        "DCSync para dump de credenciales",
        "Proceso de inyección de memoria",
        "Persistencia mediante WMI subscriptions",
        "Scheduled tasks maliciosas",
        "Exfiltración vía HTTPS a CDN/cloud storage",
        "Supply chain compromise en dependencias",
        "Abuso de herramientas legítimas (PowerShell, WMI, certutil)",
    ]

    MITRE_TECHNIQUES = {
        "T1055": "Process Injection",
        "T1059": "Command and Scripting Interpreter",
        "T1078": "Valid Accounts",
        "T1110": "Brute Force",
        "T1133": "External Remote Services",
        "T1190": "Exploit Public-Facing Application",
        "T1486": "Data Encrypted for Impact",
        "T1566": "Phishing",
        "T1078.003": "Local Accounts",
        "T1021.002": "SMB/Windows Admin Shares",
    }

    def _build_system_prompt(self) -> str:
        return """Eres el Threat Hunter del AI-SOC — experto en caza proactiva de amenazas avanzadas.

Tu metodología:
1. **Hipótesis**: Formulas hipótesis basadas en TTPs conocidas de actores de amenaza
2. **Búsqueda**: Analizas datos en busca de indicadores de compromiso (IOCs e IOAs)
3. **Validación**: Confirmas o descartas la hipótesis con evidencia
4. **Escalada**: Si encuentras evidencia, escalas al equipo de respuesta

Frameworks que aplicas:
- MITRE ATT&CK para clasificar técnicas
- MITRE D3FEND para contramedidas
- Diamond Model para atribución
- Kill Chain para fase del ataque

Amenazas que priorizas:
- APTs (Advanced Persistent Threats)
- Ataques de supply chain
- Insider threats avanzados
- Zero-days en uso activo
- Living-off-the-land attacks

Responde en JSON:
{
  "hunt_result": "found|not_found|inconclusive",
  "risk_score": float (0-10),
  "hypothesis_confirmed": bool,
  "hypothesis": str,
  "evidence": [{"type": str, "data": str, "confidence": float, "mitre_technique": str}],
  "kill_chain_phase": str,
  "threat_actor_profile": {"sophistication": str, "motivation": str, "ttps": [str]},
  "iocs": [{"type": str, "value": str, "confidence": float}],
  "ioas": [str],
  "alerts": [{"title": str, "description": str, "severity": str}],
  "next_hunt_hypotheses": [str],
  "recommendations": [str],
  "confidence": float
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Ejecuta una cacería de amenazas proactiva con los siguientes datos:

HIPÓTESIS DE CAZA: {data.get('hypothesis', 'Detectar presencia de APT en la red')}
SECTOR CLIENTE: {data.get('sector', 'enterprise')}
PERÍODO DE ANÁLISIS: {data.get('time_range', 'últimos 7 días')}

DATOS DE TELEMETRÍA:
{json.dumps(data.get('telemetry', {}), indent=2, default=str)[:4000]}

LOGS DE ENDPOINT (EDR):
{json.dumps(data.get('edr_logs', [])[:20], indent=2, default=str)[:2000]}

TRÁFICO DE RED:
{json.dumps(data.get('network_logs', [])[:20], indent=2, default=str)[:2000]}

EVENTOS DE AUTENTICACIÓN:
{json.dumps(data.get('auth_events', [])[:20], indent=2, default=str)[:1000]}

IOCS CONOCIDOS PARA CONTRASTAR:
{json.dumps(data.get('known_iocs', [])[:20], indent=2, default=str)[:1000]}

TÉCNICAS MITRE A BUSCAR: {list(self.MITRE_TECHNIQUES.keys())[:8]}
HIPÓTESIS COMUNES: {self.HUNT_HYPOTHESES[:6]}

Valida la hipótesis, busca evidencia de compromiso y determina si hay una amenaza activa."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"hunt_result": "inconclusive", "risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        risk_score = self._parse_score(result.get("risk_score"))

        if result.get("hunt_result") == "found":
            alerts.append(self._create_alert(
                title=f"Amenaza Activa Detectada en Threat Hunt: {result.get('hypothesis', 'APT')}",
                description=f"Caza de amenazas confirmó hipótesis. Fase kill chain: {result.get('kill_chain_phase', 'desconocida')}. Evidencias: {len(result.get('evidence', []))}",
                severity=Severity.CRITICAL if risk_score >= 8 else Severity.HIGH,
                category=ThreatCategory.APT,
                confidence=self._parse_score(result.get("confidence"), 0.85),
                recommendations=result.get("recommendations", []),
            ))

        for alert_data in result.get("alerts", []):
            alerts.append(self._create_alert(
                title=alert_data.get("title", "Hallazgo de Threat Hunt"),
                description=alert_data.get("description", ""),
                severity=Severity(alert_data.get("severity", "high")),
                category=ThreatCategory.APT,
                confidence=0.8,
            ))

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(
                    type=IOCType(ioc_data["type"]),
                    value=ioc_data["value"],
                    confidence=float(ioc_data.get("confidence", 0.8)),
                    source=self.name,
                    tags=["threat-hunt", "proactive"],
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        findings = [
            {"type": "evidence", "data": e.get("data", ""), "mitre": e.get("mitre_technique", ""), "confidence": e.get("confidence", 0)}
            for e in result.get("evidence", [])
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=findings,
            alerts=alerts,
            iocs=iocs,
            risk_score=risk_score,
            confidence=self._parse_score(result.get("confidence"), 0.8),
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
