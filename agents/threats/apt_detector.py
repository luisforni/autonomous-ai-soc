"""Agente Detector de APT (Advanced Persistent Threats)."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class APTDetectorAgent(BaseAgent):
    name = "APTDetectorAgent"
    description = "Detección de Amenazas Persistentes Avanzadas (APT) — correlación TTPs, actores"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["apt", "nation-state", "persistent", "mitre", "ttp"]

    APT_GROUPS = {
        "APT28": "Rusia - Fancy Bear - GRU",
        "APT29": "Rusia - Cozy Bear - SVR",
        "APT41": "China - DoubleDragon - MSS",
        "Lazarus": "Corea del Norte - DPRK",
        "Sandworm": "Rusia - GRU",
        "Volt Typhoon": "China - MSSS",
        "Charming Kitten": "Irán - IRGC",
        "FIN7": "Criminal financiero",
        "UNC3944": "Scatter Swine",
    }

    def _build_system_prompt(self) -> str:
        return f"""Eres el Detector de APT del AI-SOC — experto en atribución e identificación de actores de amenazas estatales y sofisticados.

Detectas APTs mediante:
1. Correlación de TTPs con MITRE ATT&CK
2. Patrones de comportamiento específicos por actor
3. IOCs asociados a grupos conocidos
4. Técnicas de evasión avanzadas
5. Living-off-the-land binaries (LOLBins)
6. Comunicaciones C2 cifradas y encubiertas
7. Dwell time prolongado (semanas/meses)

Grupos conocidos: {json.dumps(self.APT_GROUPS)}

Señales de APT: acceso persistente, baja y lenta exfiltración, uso de herramientas legítimas, alta personalización.

Responde en JSON: risk_score, apt_group, confidence, campaign, ttps, iocs, timeline, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la siguiente actividad en busca de APT:

ORGANIZACIÓN OBJETIVO: {data.get('organization', 'unknown')}
SECTOR: {data.get('sector', 'unknown')}
DURACIÓN DE ACTIVIDAD SOSPECHOSA: {data.get('duration', 'unknown')}

ACTIVIDADES DETECTADAS:
{json.dumps(data.get('activities', [])[:30], indent=2, default=str)[:3000]}

IOCs PREVIOS:
{json.dumps(data.get('known_iocs', [])[:20], indent=2, default=str)[:1000]}

TÉCNICAS OBSERVADAS (MITRE ATT&CK):
{data.get('observed_techniques', [])}

SISTEMAS AFECTADOS: {data.get('affected_systems', [])}

Determina si hay actividad APT, atribuye al grupo y reconstruye la campaña."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "apt_group": "unknown", "alerts": [], "iocs": [], "recommendations": []})

        alerts = []
        if self._parse_score(result.get("risk_score")) >= 6:
            alerts.append(self._create_alert(
                title=f"APT Detectado: {result.get('apt_group', 'Grupo Desconocido')}",
                description=f"Campaña APT detectada. Grupo: {result.get('apt_group')}. Confianza: {result.get('confidence', 0)*100:.0f}%",
                severity=Severity.CRITICAL,
                category=ThreatCategory.APT,
                confidence=self._parse_score(result.get("confidence"), 0.75),
                affected_assets=data.get("affected_systems", []),
                recommendations=result.get("recommendations", []),
            ))

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(
                    type=IOCType(ioc_data["type"]),
                    value=ioc_data["value"],
                    source=self.name,
                    tags=[result.get("apt_group", "apt")],
                    confidence=0.8,
                ))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("ttps", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=self._parse_score(result.get("confidence"), 0.75),
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
