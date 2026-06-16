"""Agente Detector de Exfiltración de Datos."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class DataExfiltrationDetectorAgent(BaseAgent):
    name = "DataExfiltrationDetectorAgent"
    description = "Detección de exfiltración de datos — DLP, tráfico anómalo, transferencias grandes"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["exfiltration", "dlp", "data-loss", "t1048", "mitre"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Exfiltración de Datos del AI-SOC. Detectas MITRE ATT&CK T1020-T1048:

Canales de exfiltración monitoreados:
- HTTP/HTTPS: grandes POST hacia IPs/dominios externos
- DNS: queries inusualmente largas (tunneling)
- FTP/SFTP hacia destinos no autorizados
- Email: grandes adjuntos a destinatarios externos
- Cloud Storage: subidas a Dropbox, Google Drive, Mega
- Canales alternativos: Slack, Telegram, pastebin
- Archivos comprimidos y cifrados antes de transferir

Métricas anómalas:
- Volumen de datos outbound > baseline
- Destinos geográficos inusuales
- Horario fuera de lo normal
- Usuario accediendo a datos que normalmente no consulta

Responde en JSON: risk_score, exfiltration_channel, data_volume_gb, destination, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta posible exfiltración de datos:

USUARIO/HOST: {data.get('user', 'unknown')} @ {data.get('hostname', 'unknown')}
VOLUMEN OUTBOUND ACTUAL: {data.get('outbound_gb', 0)} GB
BASELINE OUTBOUND: {data.get('baseline_gb', 0)} GB/día
RATIO: {data.get('outbound_gb', 0) / max(data.get('baseline_gb', 1), 1):.1f}x del normal

TRANSFERENCIAS DETECTADAS:
{json.dumps(data.get('transfers', [])[:20], indent=2, default=str)[:2000]}

ARCHIVOS ACCEDIDOS:
{json.dumps(data.get('files_accessed', [])[:20], indent=2, default=str)[:1000]}

DESTINOS EXTERNOS:
{json.dumps(data.get('external_destinations', [])[:10], indent=2, default=str)[:500]}

TIPO DE DATOS: {data.get('data_classification', 'unknown')}

Determina si hay exfiltración y estima el impacto."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Exfiltración de Datos Detectada"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL if self._parse_score(result.get("risk_score")) >= 8 else Severity.HIGH,
                category=ThreatCategory.DATA_EXFILTRATION,
                confidence=a.get("confidence", 0.82),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for dest in result.get("suspicious_destinations", []):
            if dest:
                iocs.append(IOC(type=IOCType.IP, value=str(dest), confidence=0.7, source=self.name))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "channel": result.get("exfiltration_channel"),
                "volume_gb": result.get("data_volume_gb"),
                "destination": result.get("destination"),
            }],
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
