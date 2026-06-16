"""Agente de Backup y Recuperación."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class BackupRecoveryAgent(BaseAgent):
    name = "BackupRecoveryAgent"
    description = "Gestión de backup y recuperación de emergencia — validación, RTO/RPO, restauración"
    version = "1.0.0"
    category = "incident_response"
    priority = AgentPriority.HIGH
    tags = ["backup", "recovery", "rto", "rpo", "restore", "disaster-recovery"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Backup y Recuperación del AI-SOC. Coordinas la recuperación tras un incidente:
- Evaluación de backups disponibles y su integridad
- Verificación que el backup no está comprometido (ransomware en backup)
- Cálculo de RPO: ¿cuántos datos se perderán?
- Cálculo de RTO: ¿cuánto tiempo tardará la recuperación?
- Priorización de sistemas críticos para recuperación
- Plan de recuperación paso a paso
- Testing de restauración antes de producción

Responde en JSON: risk_score, backup_inventory, recommended_restore_point, rpo_hours, rto_hours, recovery_plan, alerts."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Evalúa los backups y genera plan de recuperación:

INCIDENTE: {data.get('incident_type', 'unknown')}
SISTEMAS AFECTADOS: {data.get('affected_systems', [])}

BACKUPS DISPONIBLES:
{json.dumps(data.get('backups', [])[:15], indent=2, default=str)[:2000]}

ÚLTIMO BACKUP LIMPIO: {data.get('last_clean_backup', 'unknown')}
SISTEMAS CRÍTICOS: {data.get('critical_systems', [])}
RTO OBJETIVO: {data.get('rto_target', '4 horas')}
RPO OBJETIVO: {data.get('rpo_target', '1 hora')}

Genera el plan de recuperación optimizado."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "backup_inventory": [], "recovery_plan": [], "alerts": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Recuperación de Emergencia Requerida"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.UNKNOWN,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("backup_inventory", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("recovery_plan", []),
            raw_ai_response=response,
        )
