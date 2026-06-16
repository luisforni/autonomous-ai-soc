"""Agente de Tecnología de Decepción — Honeypots, Canary Tokens y Trampas."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class DeceptionManagerAgent(BaseAgent):
    name = "DeceptionManagerAgent"
    description = "Gestión de tecnología de decepción — honeypots, canary tokens y trampas activas"
    version = "1.0.0"
    category = "analytics"
    priority = AgentPriority.HIGH
    tags = ["deception", "honeypot", "canary", "honeytokens", "active-defense"]

    DECEPTION_ASSETS = [
        "honeypot_server",
        "canary_file",
        "canary_token_email",
        "canary_token_url",
        "fake_credential",
        "honey_database",
        "decoy_admin_account",
        "fake_api_key",
        "honey_network_share",
        "canary_dns_entry",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Tecnología de Decepción del AI-SOC.

Tu función es gestionar e interpretar señales de activos de decepción desplegados en la infraestructura:

**Tipos de activos que monitoreas:**
- **Honeypots**: Servidores/servicios falsos que atraen atacantes
- **Canary Tokens**: URLs, archivos, credenciales que alertan al ser accedidos
- **Honey Credentials**: Cuentas falsas en AD/LDAP
- **Honey Databases**: Bases de datos con datos falsos pero monitoreados
- **Decoy Files**: Archivos con nombres atractivos (passwords.xlsx, secrets.txt)

**Principio clave**: Cualquier interacción con un activo de decepción es una señal de ALTO VALOR — implica que:
1. El atacante ya está dentro de la red (bypass del perímetro)
2. El atacante está realizando reconocimiento activo
3. La señal tiene muy bajo tasa de falsos positivos (casi 0)

**Análisis que realizas:**
1. Identificar qué activo fue activado y cómo
2. Correlacionar con otros eventos para trazar la kill chain
3. Atribuir el origen (IP, usuario, proceso)
4. Determinar el nivel de sofisticación del atacante
5. Recomendar acciones de contención inmediata

Responde en JSON:
{
  "alert_priority": "immediate|high|medium",
  "risk_score": float (0-10),
  "deception_asset_triggered": str,
  "attacker_profile": {"ip": str, "user": str, "sophistication": str, "stage": str},
  "kill_chain_stage": str,
  "lateral_movement_indicators": [str],
  "time_in_network": str,
  "iocs": [{"type": str, "value": str}],
  "alerts": [{"title": str, "description": str, "severity": str}],
  "immediate_actions": [str],
  "recommendations": [str],
  "confidence": float
}"""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Un activo de decepción fue activado. Analiza el incidente:

ACTIVO ACTIVADO: {data.get('asset_type', 'unknown')} | NOMBRE: {data.get('asset_name', 'unknown')}
TIMESTAMP: {data.get('timestamp', 'unknown')}
IP ORIGEN: {data.get('source_ip', 'unknown')}
USUARIO (si aplica): {data.get('username', 'N/A')}
PROCESO (si aplica): {data.get('process', 'N/A')}

DETALLES DE LA INTERACCIÓN:
{json.dumps(data.get('interaction_details', {}), indent=2, default=str)[:2000]}

CONTEXTO DE RED:
- Segmento: {data.get('network_segment', 'desconocido')}
- Activos cercanos: {data.get('nearby_assets', [])}
- Conexiones previas de esta IP: {data.get('previous_connections', 0)}

EVENTOS CORRELACIONADOS (últimas 2h):
{json.dumps(data.get('correlated_events', [])[:15], indent=2, default=str)[:2000]}

SECTOR CLIENTE: {data.get('sector', 'enterprise')}
ACTIVOS CRÍTICOS EN ESTE SEGMENTO: {data.get('critical_assets', [])}

Nota: Toda activación de activo de decepción debe tratarse como Señal de Alta Fidelidad.
Determina el nivel de amenaza, el atacante y las acciones inmediatas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 8, "alert_priority": "high", "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        risk_score = self._parse_score(result.get("risk_score"), 8)

        # Cualquier activación de decepción es alta prioridad por definición
        alerts.append(self._create_alert(
            title=f"Activo de Decepción Activado: {data.get('asset_name', data.get('asset_type', 'unknown'))}",
            description=(
                f"Señal de alta fidelidad: {data.get('asset_type', 'activo de decepción')} fue accedido por {data.get('source_ip', 'IP desconocida')}. "
                f"Fase kill chain: {result.get('kill_chain_stage', 'desconocida')}. "
                f"Indicador de compromiso activo en la red."
            ),
            severity=Severity.CRITICAL if result.get("alert_priority") == "immediate" else Severity.HIGH,
            category=ThreatCategory.APT,
            confidence=self._parse_score(result.get("confidence"), 0.95),
            recommendations=result.get("immediate_actions", []) + result.get("recommendations", []),
        ))

        for alert_data in result.get("alerts", []):
            alerts.append(self._create_alert(
                title=alert_data.get("title", "Alerta de Decepción"),
                description=alert_data.get("description", ""),
                severity=Severity(alert_data.get("severity", "high")),
                category=ThreatCategory.APT,
                confidence=0.9,
            ))

        iocs = []
        if data.get("source_ip"):
            iocs.append(IOC(
                type=IOCType.IP,
                value=data["source_ip"],
                confidence=0.95,
                source=self.name,
                tags=["deception", "honeypot", "attacker"],
            ))

        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(
                    type=IOCType(ioc_data["type"]),
                    value=ioc_data["value"],
                    confidence=0.9,
                    source=self.name,
                    tags=["deception"],
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("lateral_movement_indicators", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=risk_score,
            confidence=self._parse_score(result.get("confidence"), 0.9),
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
