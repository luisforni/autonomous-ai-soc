"""Agente Monitor de Actividad de Bases de Datos (DAM)."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class DatabaseActivityMonitorAgent(BaseAgent):
    name = "DatabaseActivityMonitorAgent"
    description = "Monitoreo de actividad en bases de datos — SQL injection, exfiltración, accesos no autorizados"
    version = "1.0.0"
    category = "monitoring"
    priority = AgentPriority.HIGH
    tags = ["database", "dam", "sql", "mysql", "postgresql", "oracle"]

    def _build_system_prompt(self) -> str:
        return """Eres el Monitor de Actividad de Bases de Datos del AI-SOC. Analizas queries SQL y actividad de DB para detectar:
- SQL Injection y ataques de inyección
- Exfiltración masiva de datos (SELECT *)
- Accesos fuera de horario o desde IPs no autorizadas
- Escalada de privilegios en la DB
- Creación/modificación de cuentas de DB
- Dump de tablas sensibles (usuarios, contraseñas, tarjetas)
- Stored procedures maliciosos

Responde en JSON: risk_score, query_stats, suspicious_queries, alerts, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la siguiente actividad en base de datos:

MOTOR DB: {data.get('db_engine', 'MySQL')}
SERVIDOR: {data.get('server', 'desconocido')}
USUARIO DB: {data.get('db_user', 'unknown')}
IP ORIGEN: {data.get('source_ip', 'unknown')}

QUERIES EJECUTADAS:
{json.dumps(data.get('queries', [])[:50], indent=2, default=str)[:3000]}

TABLAS ACCEDIDAS: {data.get('tables_accessed', [])}
FILAS RETORNADAS: {data.get('rows_returned', 0)}
HORARIO NORMAL: {data.get('business_hours', '09:00-18:00')}

Detecta actividades maliciosas y accesos no autorizados."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "suspicious_queries": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Actividad Sospechosa en DB"),
                description=a.get("description", ""),
                severity=Severity(a.get("severity", "high")),
                category=ThreatCategory.DATA_EXFILTRATION,
                confidence=a.get("confidence", 0.8),
                affected_assets=[data.get("server", "unknown")],
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=result.get("suspicious_queries", []),
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.85,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
