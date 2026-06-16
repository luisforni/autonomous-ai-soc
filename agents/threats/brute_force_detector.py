"""Agente Detector de Fuerza Bruta."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class BruteForceDetectorAgent(BaseAgent):
    name = "BruteForceDetectorAgent"
    description = "Detección de ataques de fuerza bruta — SSH, RDP, web login, credential stuffing"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.HIGH
    tags = ["brute-force", "ssh", "rdp", "credential-stuffing", "password-spray"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Fuerza Bruta del AI-SOC. Detectas ataques de autenticación:
- Brute force SSH: múltiples intentos fallidos desde una IP
- RDP brute force: intentos de acceso remoto
- Web application brute force: login forms, APIs
- Credential stuffing: listas de credenciales comprometidas de brechas
- Password spraying: una contraseña, muchos usuarios
- MFA bypass attempts
- Account enumeration

Umbral de detección: >10 fallos en 1 minuto, >50 en 1 hora.

Responde en JSON: risk_score, attack_type, source_ips, target_accounts, attempts_count, success_detected, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta ataques de fuerza bruta:

SERVICIO: {data.get('service', 'SSH')}
TIEMPO: {data.get('time_window', '1h')}

INTENTOS FALLIDOS POR IP:
{json.dumps(data.get('failed_by_ip', {})[:20] if isinstance(data.get('failed_by_ip'), list) else data.get('failed_by_ip', {}), indent=2, default=str)[:2000]}

CUENTAS ATACADAS:
{json.dumps(data.get('attacked_accounts', [])[:20], indent=2, default=str)[:1000]}

TOTAL FALLOS: {data.get('total_failures', 0)}
TOTAL ÉXITOS: {data.get('total_successes', 0)}
INTENTOS POR SEGUNDO: {data.get('attempts_per_second', 0)}

¿ÉXITO DESPUÉS DE FALLOS?: {data.get('success_after_failures', False)}

Determina si es fuerza bruta y si hubo compromiso exitoso."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "source_ips": [], "recommendations": []})

        severity = Severity.CRITICAL if result.get("success_detected") else Severity.HIGH
        alerts = [
            self._create_alert(
                title=a.get("title", f"Fuerza Bruta en {data.get('service', 'Servicio')}"),
                description=a.get("description", ""),
                severity=severity,
                category=ThreatCategory.BRUTE_FORCE,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ip in result.get("source_ips", []):
            if ip:
                iocs.append(IOC(type=IOCType.IP, value=str(ip), confidence=0.85, source=self.name, tags=["brute-force"]))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"attack_type": result.get("attack_type"), "attempts": result.get("attempts_count")}],
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
