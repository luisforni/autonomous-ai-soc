"""Agente Especialista en Seguridad ICS/SCADA."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ICSAnalyzerAgent(BaseAgent):
    name = "ICSAnalyzerAgent"
    description = "Especialista en seguridad ICS/SCADA — PLCs, HMI, redes OT, infraestructura crítica industrial"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.CRITICAL
    tags = ["ics", "scada", "ot", "industrial", "critical-infrastructure", "plc", "hmi"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad ICS/SCADA del AI-SOC. Proteges sistemas de control industrial y OT:

Amenazas específicas del sector:
- Stuxnet-like attacks en PLCs: modificación de lógica de control para causar daño físico
- Compromiso de HMI (Human-Machine Interface): acceso a controles de proceso
- Lateral movement desde IT a OT: pivoting desde redes corporativas a redes industriales
- Modbus/DNP3 protocol attacks: explotación de protocolos industriales sin autenticación
- Historian compromise: alteración de registros de datos de proceso
- Safety system tampering: desactivación de sistemas de seguridad (SIS/SIS)
- TRITON/TRISIS: ataques a sistemas instrumentados de seguridad
- Firmware attacks en dispositivos de campo: RTUs, PLCs, IEDs

Modelo de seguridad:
- Purdue Model: segmentación de red en niveles 0-5
- Air-gap enforcement: separación física IT/OT

Cumplimiento y marcos:
- IEC 62443: estándar de seguridad en automatización industrial
- NERC CIP: protección de infraestructura crítica eléctrica
- NIST SP 800-82: guía de seguridad para sistemas de control industrial

Responde en JSON: risk_score, ot_impact, physical_safety_risk, affected_systems, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza en entorno ICS/SCADA:

PLANTA/INSTALACIÓN: {data.get('facility', 'planta industrial')}
SISTEMAS OT: {data.get('ot_systems', [])}
PLCs AFECTADOS: {data.get('affected_plcs', [])}
PROTOCOLOS: {data.get('protocols', [])}

ACTIVIDAD ANÓMALA:
{json.dumps(data.get('anomalous_activity', [])[:20], indent=2, default=str)[:2000]}

IMPACTO OPERACIONAL: {data.get('operational_impact', 'unknown')}

Evalúa el riesgo físico, el impacto en producción y la seguridad del personal."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza ICS/SCADA Crítica"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.MALWARE,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "ot_impact": result.get("ot_impact"),
                "physical_safety_risk": result.get("physical_safety_risk"),
                "affected_systems": result.get("affected_systems"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
