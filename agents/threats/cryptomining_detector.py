"""Agente Detector de Cryptomining."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, IOC, IOCType, Severity, ThreatCategory


class CryptominingDetectorAgent(BaseAgent):
    name = "CryptominingDetectorAgent"
    description = "Detección de cryptomining no autorizado — XMRig, mining pools, CPU abuse"
    version = "1.0.0"
    category = "threats"
    priority = AgentPriority.HIGH
    tags = ["cryptomining", "xmrig", "monero", "cpu", "resources"]

    MINING_POOLS = [
        "pool.supportxmr.com", "xmrpool.eu", "mine.xmrpool.net",
        "crypto-pool.fr", "minexmr.com", "hashvault.pro",
        "c3pool.com", "nanopool.org",
    ]

    def _build_system_prompt(self) -> str:
        return """Eres el Detector de Cryptomining del AI-SOC. Detectas minería no autorizada:
- Procesos con alta CPU persistente (>80%)
- Conexiones a puertos de mining pools (3333, 4444, 5555, 7777, 14444)
- Proceso xmrig, minerd, cgminer u otros miners
- Conexiones a dominios de pools conocidos
- Container crypto-jacking en K8s
- Cryptomining en funciones serverless
- Browser cryptomining (CoinHive-like en aplicaciones web)

Responde en JSON: risk_score, miner_type, crypto_currency, pool_address, affected_systems, cost_per_day_usd, alerts, iocs, recommendations."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Detecta cryptomining no autorizado:

CPU USAGE PROMEDIO: {data.get('avg_cpu_pct', 0)}%
PROCESOS CON ALTO CPU:
{json.dumps(data.get('high_cpu_processes', [])[:10], indent=2, default=str)[:1000]}

CONEXIONES ACTIVAS:
{json.dumps(data.get('connections', [])[:20], indent=2, default=str)[:1500]}

POOLS CONOCIDOS EN BLACKLIST:
{self.MINING_POOLS[:5]}

SISTEMAS AFECTADOS: {data.get('affected_hosts', [])}
INSTANCIAS CLOUD SOSPECHOSAS: {data.get('suspicious_instances', [])}

Confirma si hay minería ilícita y estima el costo para el cliente."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "pool_address": "unknown", "iocs": [], "recommendations": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Cryptomining No Autorizado Detectado"),
                description=a.get("description", ""),
                severity=Severity.HIGH,
                category=ThreatCategory.CRYPTOMINING,
                confidence=a.get("confidence", 0.88),
                affected_assets=result.get("affected_systems", []),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        iocs = []
        if result.get("pool_address"):
            iocs.append(IOC(type=IOCType.DOMAIN, value=str(result["pool_address"]), confidence=0.9, source=self.name, tags=["mining-pool"]))

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{"miner": result.get("miner_type"), "currency": result.get("crypto_currency"), "cost_usd_day": result.get("cost_per_day_usd")}],
            alerts=alerts,
            iocs=iocs,
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("recommendations", []),
            raw_ai_response=response,
        )
