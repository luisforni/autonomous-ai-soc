"""Agente SOAR Orchestrator — Orquestación de respuesta automatizada."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class SOAROrchestatorAgent(BaseAgent):
    name = "SOAROrchestatorAgent"
    description = "Orquestación de respuesta automatizada a incidentes — playbooks y workflows"
    version = "1.0.0"
    category = "analytics"
    priority = AgentPriority.CRITICAL
    tags = ["soar", "automation", "playbook", "orchestration", "response", "workflow"]

    PLAYBOOKS = {
        "ransomware": ["aislar_host", "bloquear_ip_c2", "snapshot_memoria", "notificar_ciso", "activar_backup_recovery"],
        "phishing": ["bloquear_email_sender", "analizar_adjuntos", "revocar_credenciales_si_comprometidas", "notificar_usuario"],
        "brute_force": ["bloquear_ip_origen", "forzar_mfa", "revisar_logs_previos", "notificar_usuario"],
        "data_exfiltration": ["bloquear_destino", "aislar_host", "capturar_evidencia", "notificar_legal"],
        "malware": ["aislar_host", "snapshot_disco", "análisis_forense", "limpiar_o_reimaginar"],
        "insider_threat": ["revocar_accesos", "preservar_evidencia", "notificar_rrhh", "notificar_legal"],
        "apt": ["no_alertar_atacante", "activar_threat_hunt", "recolectar_iocs", "notificar_ciso", "activar_deception"],
    }

    def _build_system_prompt(self) -> str:
        return """Eres el Orquestador SOAR (Security Orchestration, Automation and Response) del AI-SOC.

Tu función es determinar y ejecutar el playbook de respuesta apropiado ante incidentes de seguridad:

**Capacidades:**
1. **Selección de Playbook**: Eliges el playbook correcto basándote en el tipo de incidente
2. **Priorización**: Ordenas las acciones por impacto y urgencia
3. **Automatización**: Determinas qué acciones ejecutar automáticamente vs requerir aprobación humana
4. **Integración**: Coordinas con herramientas externas (SIEM, EDR, Firewall, AD, ticketing)
5. **Escalada**: Determinas cuándo escalar a analistas humanos

**Reglas de automatización:**
- AUTOMÁTICO: bloqueos de IP, cuarentena de hosts, revocación de tokens, actualizaciones de firewall
- APROBACIÓN HUMANA: aislamiento de servidores críticos, revocación de cuentas VIP, comunicación externa
- SIEMPRE HUMANO: desconexión de sistemas de producción críticos, comunicación con reguladores

**Integraciones disponibles:**
- SIEM (Splunk/Elastic/QRadar)
- EDR (CrowdStrike/SentinelOne/Defender)
- Firewall (Palo Alto/Fortinet/Check Point)
- Active Directory
- Ticketing (Jira/ServiceNow)
- Comunicación (Slack/Teams/PagerDuty)
- Threat Intel (VirusTotal/MISP/OTX)

Responde en JSON:
{
  "incident_type": str,
  "playbook_selected": str,
  "risk_score": float,
  "actions": [
    {
      "step": int,
      "action": str,
      "integration": str,
      "automated": bool,
      "requires_approval": bool,
      "estimated_time": str,
      "rollback_plan": str
    }
  ],
  "escalation_required": bool,
  "escalation_reason": str,
  "notifications": [{"target": str, "channel": str, "message": str, "urgency": str}],
  "sla_deadline": str,
  "alerts": [{"title": str, "description": str, "severity": str}],
  "recommendations": [str],
  "confidence": float
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Orquesta la respuesta al siguiente incidente de seguridad:

TIPO DE INCIDENTE: {data.get('incident_type', 'desconocido')}
SEVERIDAD: {data.get('severity', 'high')}
ACTIVOS AFECTADOS: {data.get('affected_assets', [])}
SECTOR: {data.get('sector', 'enterprise')}

DESCRIPCIÓN DEL INCIDENTE:
{data.get('description', 'No hay descripción disponible')}

ALERTAS RELACIONADAS:
{json.dumps(data.get('related_alerts', [])[:10], indent=2, default=str)[:2000]}

IOCs IDENTIFICADOS:
{json.dumps(data.get('iocs', [])[:20], indent=2, default=str)[:1000]}

CONTEXTO DEL ENTORNO:
- Activos críticos en riesgo: {data.get('critical_assets_at_risk', [])}
- Ventana de negocio activa: {data.get('business_hours', True)}
- Aprobadores disponibles: {data.get('approvers_available', True)}
- SLA restante: {data.get('sla_remaining', 'desconocido')}

PLAYBOOKS DISPONIBLES: {list(self.PLAYBOOKS.keys())}

Selecciona el playbook apropiado y genera el plan de respuesta paso a paso."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 5, "playbook_selected": "unknown", "actions": [], "alerts": [], "recommendations": []})

        alerts = []
        risk_score = self._parse_score(result.get("risk_score"), 5)

        alerts.append(self._create_alert(
            title=f"SOAR Activado: Playbook '{result.get('playbook_selected', 'desconocido')}'",
            description=(
                f"Orquestación iniciada para incidente tipo '{data.get('incident_type', 'unknown')}'. "
                f"Acciones planificadas: {len(result.get('actions', []))}. "
                f"Escalada requerida: {result.get('escalation_required', False)}"
            ),
            severity=Severity.HIGH if risk_score >= 7 else Severity.MEDIUM,
            category=ThreatCategory.UNKNOWN,
            confidence=self._parse_score(result.get("confidence"), 0.9),
            recommendations=result.get("recommendations", []),
        ))

        for alert_data in result.get("alerts", []):
            alerts.append(self._create_alert(
                title=alert_data.get("title", "Acción SOAR"),
                description=alert_data.get("description", ""),
                severity=Severity(alert_data.get("severity", "medium")),
                category=ThreatCategory.UNKNOWN,
                confidence=0.9,
            ))

        try:
            raw_conf = float(result.get("confidence", 0.9))
            confidence = raw_conf / 10.0 if raw_conf > 1.0 else raw_conf
        except (TypeError, ValueError):
            confidence = 0.9

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("actions", []),
            alerts=alerts,
            iocs=[],
            risk_score=risk_score,
            confidence=confidence,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
