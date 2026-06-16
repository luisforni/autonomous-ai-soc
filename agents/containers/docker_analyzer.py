"""Agente Analizador Docker."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class DockerAnalyzerAgent(BaseAgent):
    name = "DockerAnalyzerAgent"
    description = "Análisis de seguridad Docker — daemon, contenedores en ejecución, configuración"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.HIGH
    tags = ["docker", "containers", "daemon", "security", "cis"]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de Seguridad Docker del AI-SOC. Analizas entornos Docker:
- Docker daemon expuesto sin TLS
- Contenedores ejecutando como root
- Contenedores privilegiados
- Volúmenes montando paths críticos del host (/etc, /var/run/docker.sock)
- Imágenes sin escanear o con CVEs críticos
- Network mode host
- Contenedores sin resource limits
- CIS Docker Benchmark compliance
- Actividad sospechosa en contenedores

Responde en JSON: risk_score, docker_daemon_issues, container_findings, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del entorno Docker:

HOST: {data.get('hostname', 'unknown')}
DOCKER VERSION: {data.get('docker_version', 'unknown')}
DAEMON CONFIG: {json.dumps(data.get('daemon_config', {}), default=str)}

CONTENEDORES EN EJECUCIÓN:
{json.dumps(data.get('containers', [])[:20], indent=2, default=str)[:2000]}

IMÁGENES:
{json.dumps(data.get('images', [])[:15], indent=2, default=str)[:1000]}

Detecta contenedores inseguros y configuraciones del daemon riesgosas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "container_findings": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Riesgo Docker"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.85),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("container_findings", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
