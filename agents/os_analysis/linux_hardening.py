"""Agente de Hardening Linux — CIS Benchmarks."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class LinuxHardeningAgent(BaseAgent):
    name = "LinuxHardeningAgent"
    description = "Verificación de hardening Linux según CIS Benchmarks y STIG"
    version = "1.0.0"
    category = "os_analysis"
    priority = AgentPriority.MEDIUM
    tags = ["hardening", "linux", "cis", "stig", "compliance", "baseline"]

    def _build_system_prompt(self) -> str:
        return """Eres el Agente de Hardening Linux del AI-SOC. Verificas configuraciones de seguridad según:
- CIS Benchmark para Linux (RHEL, Ubuntu, Debian, CentOS)
- DISA STIG para Linux
- NSA/CISA guidelines

Evalúas:
- Configuración de SSH (sin root login, sin passwords, ciphers)
- Permisos de archivos críticos
- Servicios innecesarios activos
- Configuración de firewall (iptables/nftables)
- Kernel parameters (sysctl)
- PAM y política de contraseñas
- Auditoría del sistema (auditd)
- SELinux/AppArmor status
- Actualizaciones de seguridad pendientes

Responde en JSON: risk_score, hardening_score (0-100), failed_controls, passed_controls, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Evalúa el hardening del sistema Linux:

SISTEMA: {data.get('hostname', 'unknown')} | {data.get('distro', 'Linux')}

CONFIGURACIÓN SSH:
{json.dumps(data.get('ssh_config', {}), indent=2, default=str)}

SYSCTL PARAMS:
{json.dumps(data.get('sysctl', {}), indent=2, default=str)[:1000]}

SERVICIOS ACTIVOS:
{json.dumps(data.get('services', [])[:30], indent=2, default=str)[:1000]}

USUARIOS SIN CONTRASEÑA:
{data.get('users_no_password', [])}

SUID FILES:
{data.get('suid_files', [])[:20]}

SELINUX/APPARMOR:
{data.get('mac_status', 'unknown')}

Genera puntuación de hardening e identifica los controles fallidos más críticos."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 5, "hardening_score": 50, "alerts": [], "failed_controls": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Control de Hardening Fallido"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "medium")),
                category=ThreatCategory.VULNERABILITY,
                confidence=0.95,
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("failed_controls", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.92,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
