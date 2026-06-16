"""Agente AWS CloudTrail Analyzer."""

from __future__ import annotations

import json
from typing import Any

from agents.cloud.base_cloud_agent import BaseCloudAgent
from core.base_agent import AgentPriority
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class AWSCloudTrailAnalyzerAgent(BaseCloudAgent):
    name = "AWSCloudTrailAnalyzerAgent"
    description = "Análisis de AWS CloudTrail — detección de actividad maliciosa en API calls"
    version = "1.0.0"
    category = "cloud"
    priority = AgentPriority.HIGH
    provider = "AWS"
    tags = ["aws", "cloudtrail", "api", "audit", "activity"]

    SUSPICIOUS_APIS = [
        "CreateUser", "AttachUserPolicy", "AttachRolePolicy",
        "PutUserPolicy", "CreateAccessKey", "CreateLoginProfile",
        "StopLogging", "DeleteTrail", "PutEventSelectors",
        "AuthorizeSecurityGroupIngress", "CreateKeyPair",
        "GetSecretValue", "ListBuckets", "GetObject",
        "RunInstances", "TerminateInstances",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Analizador de AWS CloudTrail del AI-SOC. Detectas amenazas en logs de CloudTrail:
- Reconocimiento: ListBuckets, DescribeInstances, GetAccountAuthorizationDetails
- Escalada IAM: CreateUser, AttachPolicy, PutRolePolicy
- Evasión: StopLogging, DeleteTrail, DisableGuardDuty
- Persistencia: CreateAccessKey, CreateLoginProfile
- Exfiltración: GetObject masivo, CreateSnapshot
- Accesos desde IPs anómalas o países no habituales
- Uso fuera de horario

Responde en JSON: risk_score, api_summary, attack_sequence, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        events = data.get("events", [])
        suspicious = [e for e in events if e.get("eventName") in self.SUSPICIOUS_APIS]
        return f"""Analiza los eventos de CloudTrail:

CUENTA: {data.get('account_id', 'unknown')}
TOTAL EVENTOS: {len(events)}
EVENTOS SOSPECHOSOS PRE-DETECTADOS: {len(suspicious)}

EVENTOS CLOUDTRAIL:
{json.dumps(events[:100], indent=2, default=str)[:4000]}

APIS MONITOREADAS: {self.SUSPICIOUS_APIS[:10]}

Detecta la secuencia del ataque y genera alertas."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "attack_sequence": [], "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Actividad Maliciosa en AWS"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory(a.get("category", "unknown")),
                confidence=a.get("confidence", 0.85),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        for ioc_data in result.get("iocs", []):
            try:
                iocs.append(IOC(type=IOCType(ioc_data["type"]), value=ioc_data["value"], source=self.name))
            except (ValueError, KeyError, TypeError, AttributeError):
                continue

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("attack_sequence", []),
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.87,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
