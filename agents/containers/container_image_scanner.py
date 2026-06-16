"""Agente Scanner de Imágenes de Contenedores."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class ContainerImageScannerAgent(BaseAgent):
    name = "ContainerImageScannerAgent"
    description = "Escaneo de imágenes de contenedores — CVEs, secretos, malware, mejores prácticas"
    version = "1.0.0"
    category = "containers"
    priority = AgentPriority.HIGH
    tags = ["container", "image", "scan", "cve", "trivy", "snyk"]

    def _build_system_prompt(self) -> str:
        return """Eres el Escáner de Imágenes de Contenedores del AI-SOC. Analizas imágenes para detectar:
- CVEs críticos en OS packages y librerías de aplicación
- Secretos hardcodeados (API keys, passwords, tokens)
- Malware y backdoors en layers
- Imagen base desactualizada o insegura
- Binarios SUID/SGID innecesarios
- Ejecución como root (USER no definido)
- Puertos expuestos innecesarios
- Imagen con demasiados layers o tamaño excesivo

Responde en JSON: risk_score, image_info, cve_summary, secrets_found, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la imagen de contenedor:

IMAGEN: {data.get('image_name', 'unknown')}:{data.get('tag', 'latest')}
DIGEST: {data.get('digest', 'unknown')}
BASE IMAGE: {data.get('base_image', 'unknown')}
TAMAÑO: {data.get('size_mb', 0)} MB

CVEs DETECTADOS:
{json.dumps(data.get('cves', [])[:30], indent=2, default=str)[:2000]}

SECRETOS ENCONTRADOS:
{json.dumps(data.get('secrets', [])[:10], indent=2, default=str)[:500]}

DOCKERFILE ISSUES:
{json.dumps(data.get('dockerfile_issues', []), indent=2, default=str)}

Evalúa el riesgo y genera recomendaciones de hardening."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "cve_summary": {}, "secrets_found": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Imagen Insegura"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.VULNERABILITY,
                confidence=a.get("confidence", 0.9),
                affected_assets=[f"{data.get('image_name')}:{data.get('tag')}"],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("secrets_found", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
