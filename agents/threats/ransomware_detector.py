"""Agente Detector de Ransomware."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class RansomwareDetectorAgent(BaseAgent):
    name = "RansomwareDetectorAgent"
    description = "Detección temprana de ransomware — patrones de cifrado, IOCs, comportamiento"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["ransomware", "encryption", "lockbit", "ryuk", "conti", "blackcat"]

    RANSOMWARE_FAMILIES = [
        "LockBit", "BlackCat/ALPHV", "Conti", "Ryuk", "REvil/Sodinokibi",
        "BlackMatter", "Hive", "Royal", "Play", "Akira", "8Base",
        "Cl0p", "MedusaLocker", "Cuba", "Vice Society",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Ransomware del AI-SOC — experto en detección temprana antes del cifrado masivo.

Detectas indicadores de ransomware en sus fases:
1. Pre-ransom: reconocimiento interno, movimiento lateral, exfiltración previa
2. Preparación: deshabilitación de backups (vssadmin, bcdedit), borrado de shadow copies
3. Ejecución: procesos con alta actividad de I/O, extensiones de archivo cambiando, entropy aumentando
4. Post-ransom: nota de rescate, cambio de fondo de pantalla, contacto con C2

IOCs específicos por familia: extensiones de cifrado, notas de rescate, paths C2.

Responde en JSON: risk_score, ransomware_family, attack_phase, critical_indicators, affected_systems, alerts, iocs, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta posible actividad de ransomware:

SISTEMA: {data.get('hostname', 'unknown')}
HORA DE DETECCIÓN: {data.get('timestamp', 'unknown')}

ACTIVIDAD DE ARCHIVOS (últimos 5 min):
- Archivos modificados: {data.get('files_modified', 0)}
- Archivos renombrados: {data.get('files_renamed', 0)}
- Archivos eliminados: {data.get('files_deleted', 0)}
- Extensiones nuevas detectadas: {data.get('new_extensions', [])}

PROCESOS SOSPECHOSOS:
{json.dumps(data.get('suspicious_processes', [])[:15], indent=2, default=str)[:1500]}

COMANDOS EJECUTADOS:
{json.dumps(data.get('commands', [])[:20], indent=2, default=str)[:1000]}

SHADOW COPIES: {data.get('shadow_copies_deleted', False)}
BACKUPS ACCEDIDOS: {data.get('backup_access', False)}
CONEXIONES C2: {data.get('c2_connections', [])}

FAMILIAS DE REFERENCIA: {self.RANSOMWARE_FAMILIES[:8]}

Determina si hay ransomware activo y qué acciones inmediatas tomar."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "ransomware_family": "none", "alerts": [], "iocs": [], "immediate_actions": []})

        alerts = []
        if self._parse_score(result.get("risk_score")) >= 6:
            alerts.append(self._create_alert(
                title=f"ALERTA RANSOMWARE: {result.get('ransomware_family', 'Desconocido')}",
                description=f"Actividad de ransomware detectada en {data.get('hostname')}. Fase: {result.get('attack_phase', 'unknown')}",
                severity=Severity.CRITICAL,
                category=ThreatCategory.RANSOMWARE,
                confidence=self._parse_score(result.get("confidence"), 0.85),
                affected_assets=[data.get("hostname", "unknown")],
                recommendations=result.get("immediate_actions", []),
            ))

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name, confidence=0.85))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("critical_indicators", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=self._parse_score(result.get("confidence"), 0.85),
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
