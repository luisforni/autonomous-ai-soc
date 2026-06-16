"""Agente Especialista en Seguridad Móvil."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class MobileSecurityAgent(BaseAgent):
    name = "MobileSecurityAgent"
    description = "Especialista en seguridad móvil — iOS, Android, MDM, BYOD, malware móvil"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.HIGH
    tags = ["mobile", "ios", "android", "mdm", "byod", "mobile-malware", "mobileapps"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad Móvil del AI-SOC. Proteges dispositivos móviles y entornos BYOD:

Amenazas específicas del sector:
- Mobile malware: spyware (Pegasus, FinFisher), stalkerware, banking trojans (Anubis, Cerberus)
- App store threats: apps maliciosas en Google Play / App Store, sideloading
- MDM bypass: evasión de gestión de dispositivos móviles, enrollamiento fraudulento
- Jailbreak/root detection evasion: dispositivos comprometidos accediendo a recursos corporativos
- Man-in-the-middle en redes WiFi públicas: intercepción de tráfico cifrado
- SMS phishing (smishing): suplantación de bancos, servicios y empresas por SMS
- SIM swapping: transferencia fraudulenta de número de teléfono para robo de 2FA
- Rogue access points: puntos de acceso falsos para interceptar comunicaciones
- Mobile ransomware: cifrado de datos en dispositivos móviles

Cumplimiento y marcos:
- OWASP Mobile Top 10: principales riesgos en aplicaciones móviles
- CIS Mobile: benchmarks de seguridad para iOS y Android
- NIST SP 800-124: directrices para gestión de dispositivos móviles

Responde en JSON: risk_score, platform, malware_type, data_at_risk, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza en dispositivo móvil:

DISPOSITIVO: {data.get('device_info', 'dispositivo móvil')}
PLATAFORMA: {data.get('platform', 'unknown')}
APPS SOSPECHOSAS: {data.get('suspicious_apps', [])}

ACTIVIDAD DE RED:
{json.dumps(data.get('network_activity', [])[:20], indent=2, default=str)[:2000]}

MDM STATUS: {data.get('mdm_status', 'unknown')}
DATOS EN RIESGO: {data.get('data_at_risk', [])}

Evalúa el riesgo de comprometimiento del dispositivo y exposición de datos corporativos."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza Móvil Detectada"),
                description=a.get("description", ""),
                severity=Severity.HIGH,
                category=ThreatCategory.MALWARE,
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "platform": result.get("platform"),
                "malware_type": result.get("malware_type"),
                "data_at_risk": result.get("data_at_risk"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
