"""Agente Detector de Rootkits."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class RootkitDetectorAgent(BaseAgent):
    name = "RootkitDetectorAgent"
    description = "Detección de rootkits — kernel, userland, bootkits, hypervisor rootkits"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.CRITICAL
    tags = ["rootkit", "kernel", "bootkit", "stealth", "persistence"]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Rootkits del AI-SOC. Detectas técnicas de ocultamiento avanzadas:

Tipos de rootkits:
- Kernel rootkits (ring 0): módulos maliciosos del kernel, hooking de syscalls
- Userland rootkits: LD_PRELOAD, DLL injection, hooking de libc
- Bootkits: MBR/VBR/UEFI comprometidos
- Hypervisor rootkits: virtualización del OS víctima
- Firmware rootkits: BIOS/UEFI persistente

Técnicas de detección:
- Discrepancias entre lo visible a nivel de usuario vs kernel
- Módulos del kernel no firmados o anómalos
- Hooking de syscalls (sys_call_table modificada)
- Procesos visibles en /proc pero no en ps
- Archivos visibles en debugfs pero no en ls
- DKOM (Direct Kernel Object Manipulation)

Responde en JSON: risk_score, rootkit_type, stealth_techniques, hidden_objects, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta presencia de rootkit:

SISTEMA: {data.get('hostname', 'unknown')} | {data.get('os', 'Linux')}
KERNEL: {data.get('kernel_version', 'unknown')}

MÓDULOS DEL KERNEL:
{json.dumps(data.get('kernel_modules', [])[:30], indent=2, default=str)[:1500]}

DISCREPANCIAS DETECTADAS:
- Procesos en /proc no en ps: {data.get('hidden_processes', [])}
- Archivos en debugfs no en ls: {data.get('hidden_files', [])}
- Conexiones no visibles: {data.get('hidden_connections', [])}

SYSCALL TABLE MODIFICADA: {data.get('syscall_modified', False)}
HOOKING DETECTADO: {data.get('hooks_detected', [])}

Determina si hay un rootkit activo y cómo fue instalado."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "stealth_techniques": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Rootkit Detectado"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.ROOTKIT,
                confidence=a.get("confidence", 0.82),
                affected_assets=[data.get("hostname", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("stealth_techniques", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.82,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
