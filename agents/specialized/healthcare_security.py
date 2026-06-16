"""Agente Especialista en Seguridad Hospitalaria."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class HealthcareSecurityAgent(BaseAgent):
    name = "HealthcareSecurityAgent"
    description = "Especialista en seguridad hospitalaria — HIPAA, HL7, DICOM, dispositivos médicos"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.CRITICAL
    tags = ["healthcare", "hipaa", "hospital", "medical-devices", "hl7", "dicom", "phi"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad Hospitalaria del AI-SOC. Proteges hospitales y sistemas de salud:

Amenazas específicas del sector:
- Ransomware en hospitales: riesgo de vida (equipos médicos desconectados)
- Robo de PHI (Protected Health Information): registros médicos
- Compromiso de dispositivos médicos (IoMT): bombas de insulina, monitores
- HL7 FHIR API vulnerabilidades: exposición de datos de pacientes
- DICOM security: imágenes médicas expuestas
- EHR/EMR compromise: sistemas de registros electrónicos
- Suplantación de prescripciones o resultados de laboratorio

Cumplimiento:
- HIPAA: 18 identificadores PHI protegidos
- HITECH: notificación de brechas de salud
- FDA: regulación de software médico
- HITRUST: framework de seguridad sanitaria

Responde en JSON: risk_score, phi_exposure_risk, patient_safety_risk, regulatory_risk, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza en entorno hospitalario:

INSTITUCIÓN: {data.get('institution', 'hospital')}
SISTEMAS AFECTADOS: {data.get('systems', [])}
DISPOSITIVOS MÉDICOS AFECTADOS: {data.get('medical_devices', [])}

ACTIVIDAD SOSPECHOSA:
{json.dumps(data.get('suspicious_activity', [])[:20], indent=2, default=str)[:2000]}

PHI EN RIESGO: {data.get('phi_at_risk', 0)} registros
IMPACTO EN OPERACIONES CLÍNICAS: {data.get('clinical_impact', 'unknown')}

Evalúa el riesgo para los pacientes y el compliance HIPAA."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza Hospitalaria Crítica"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.RANSOMWARE,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"phi_risk": result.get("phi_exposure_risk"), "patient_safety": result.get("patient_safety_risk")}],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
