"""Agente Especialista en Seguridad de Código."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class CodeSecurityAgent(BaseAgent):
    name = "CodeSecurityAgent"
    description = "Especialista en seguridad de código — SAST, SCA, secrets, DevSecOps, supply chain"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.HIGH
    tags = ["code-security", "sast", "sca", "secrets", "devsecops", "supply-chain", "dependencies"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad de Código del AI-SOC. Proteges el ciclo de desarrollo de software:

Amenazas específicas del sector:
- SAST findings: SQL injection, XSS, command injection, path traversal, insecure deserialization en código fuente
- Secrets hardcoded: API keys, passwords, tokens JWT, certificados privados embebidos en código
- Vulnerable dependencies: CVEs críticos en paquetes npm/pip/maven/gradle/cargo
- Supply chain attacks: paquetes maliciosos en registros (typosquatting, dependency confusion)
- IaC misconfigurations: S3 buckets públicos en Terraform, puertos abiertos en Ansible, RBAC permisivos en Helm
- Container image vulnerabilities: capas base desactualizadas, binarios con vulnerabilidades conocidas
- License compliance: dependencias con licencias incompatibles (GPL en código propietario)
- Code signing bypass: commits sin firma, pipelines sin verificación de integridad

Cumplimiento y marcos:
- OWASP Top 10: principales vulnerabilidades en aplicaciones web
- OWASP SAMM: Software Assurance Maturity Model
- CWE/SANS Top 25: debilidades de software más peligrosas

Responde en JSON: risk_score, critical_vulns, secrets_found, dependency_vulns, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la seguridad del código:

REPOSITORIO: {data.get('repository', 'repositorio')}
LENGUAJE: {data.get('language', 'unknown')}

HALLAZGOS SAST:
{json.dumps(data.get('sast_findings', [])[:20], indent=2, default=str)[:2000]}

DEPENDENCIAS VULNERABLES:
{json.dumps(data.get('vulnerable_deps', [])[:20], indent=2, default=str)[:1000]}

SECRETOS DETECTADOS: {data.get('secrets_found', [])[:10]}
IaC ISSUES: {data.get('iac_issues', [])[:10]}

Evalúa el riesgo de explotación, exposición de secretos y vulnerabilidades en la cadena de suministro de software."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Vulnerabilidad de Código Detectada"),
                description=a.get("description", ""),
                severity=Severity.HIGH,
                category=ThreatCategory.VULNERABILITY,
                confidence=a.get("confidence", 0.9),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "critical_vulns": result.get("critical_vulns"),
                "secrets_found": result.get("secrets_found"),
                "dependency_vulns": result.get("dependency_vulns"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.9,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
