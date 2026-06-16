"""Agente Especialista en Seguridad IoT."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class IoTSecurityAgent(BaseAgent):
    name = "IoTSecurityAgent"
    description = "Especialista en seguridad IoT — firmware, MQTT, botnets, Mirai, dispositivos embebidos"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.HIGH
    tags = ["iot", "embedded", "firmware", "zigbee", "mqtt", "botnets", "mirai"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad IoT del AI-SOC. Proteges ecosistemas de dispositivos conectados:

Amenazas específicas del sector:
- Mirai-like botnets: reclutamiento masivo de dispositivos IoT para ataques DDoS
- Firmware vulnerabilities: buffer overflows, command injection en firmware embebido
- Default credentials: uso de credenciales de fábrica no cambiadas (admin/admin)
- Insecure MQTT/CoAP protocols: brokers MQTT expuestos sin autenticación, topic hijacking
- Physical tampering: acceso físico a dispositivos para extracción de firmware
- Supply chain backdoors: puertas traseras introducidas en fabricación
- RF attacks: ataques a comunicaciones Zigbee/Z-Wave/Bluetooth LE
- DNS rebinding: explotación de dispositivos IoT desde navegadores
- JTAG/UART debug interfaces: acceso a interfaces de depuración expuestas

Cumplimiento y marcos:
- ETSI EN 303 645: estándar europeo de ciberseguridad para consumidores IoT
- NIST IR 8259: actividades principales de ciberseguridad para fabricantes de IoT
- IoT Security Foundation: mejores prácticas para dispositivos conectados

Responde en JSON: risk_score, device_count_affected, botnet_risk, firmware_vuln, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza en entorno IoT:

DISPOSITIVOS IoT: {data.get('iot_devices', [])}
PROTOCOLOS: {data.get('protocols', [])}
FIRMWARE VERSION: {data.get('firmware_version', 'unknown')}

ACTIVIDAD DE RED:
{json.dumps(data.get('network_activity', [])[:20], indent=2, default=str)[:2000]}

VULNERABILIDADES CONOCIDAS: {data.get('known_vulns', [])}

Evalúa el riesgo de botnet, compromiso de firmware y exposición de la red."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza IoT Detectada"),
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
                "device_count_affected": result.get("device_count_affected"),
                "botnet_risk": result.get("botnet_risk"),
                "firmware_vuln": result.get("firmware_vuln"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
