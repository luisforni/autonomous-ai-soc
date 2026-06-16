"""Agente Especialista en Seguridad Blockchain/DeFi."""

from __future__ import annotations

import json
from typing import Any

from core.base_agent import AgentPriority, BaseAgent
from core.models import AgentAnalysis, Severity, ThreatCategory


class BlockchainSecurityAgent(BaseAgent):
    name = "BlockchainSecurityAgent"
    description = "Especialista en seguridad blockchain — DeFi, smart contracts, Web3, crypto wallets"
    version = "1.0.0"
    category = "specialized"
    priority = AgentPriority.HIGH
    tags = ["blockchain", "crypto", "defi", "smart-contracts", "web3", "nft", "wallet"]

    def _build_system_prompt(self) -> str:
        return """Eres el Especialista en Seguridad Blockchain/DeFi del AI-SOC. Proteges ecosistemas Web3 y activos cripto:

Amenazas específicas del sector:
- Smart contract vulnerabilities: reentrancy attacks (DAO hack), integer overflow, flash loan attacks
- Private key theft: compromiso de wallets, seed phrase phishing, clipboard hijacking
- Rugpulls: abandono fraudulento de proyectos DeFi con fondos de inversores
- Front-running attacks: MEV bots que anticipan transacciones en mempool
- Bridge exploits: vulnerabilidades en puentes cross-chain (Ronin, Wormhole)
- 51% attacks: control mayoritario del hashrate para doble gasto
- NFT scams: minting fraudulento, wash trading, robo de NFTs
- Análisis on-chain de transacciones sospechosas: mixing, tumbling, lavado de dinero crypto
- Oracle manipulation: manipulación de oráculos de precios en protocolos DeFi

Cumplimiento y marcos:
- FATF Travel Rule: regulación AML para transferencias cripto
- AML crypto: normativas anti-lavado de dinero en criptomonedas
- MiCA: Markets in Crypto-Assets regulation (Europa)

Responde en JSON: risk_score, contract_vulnerability, financial_loss_usd, attack_type, alerts, immediate_actions."""

    def _build_user_prompt(self, data: dict[str, Any]) -> str:
        return f"""Analiza la amenaza en entorno blockchain/DeFi:

PROTOCOLO/CHAIN: {data.get('blockchain_protocol', 'unknown')}
SMART CONTRACT: {data.get('contract_address', 'unknown')}
WALLETS INVOLUCRADAS: {data.get('wallets', [])}
PÉRDIDA ESTIMADA USD: {data.get('estimated_loss', 0)}

TRANSACCIONES SOSPECHOSAS:
{json.dumps(data.get('suspicious_txs', [])[:20], indent=2, default=str)[:2000]}

Evalúa el riesgo de pérdida financiera, vulnerabilidades del contrato y cumplimiento AML."""

    async def analyze(self, data: dict[str, Any]) -> AgentAnalysis:
        response = await self._query_ai(self._build_user_prompt(data))
        result = self._parse_ai_json(response, {"risk_score": 0, "alerts": [], "immediate_actions": []})

        alerts = [
            self._create_alert(
                title=a.get("title", "Amenaza Blockchain Detectada"),
                description=a.get("description", ""),
                severity=Severity.CRITICAL,
                category=ThreatCategory.FRAUD,
                confidence=a.get("confidence", 0.88),
            )
            for a in result.get("alerts", []) if isinstance(a, dict)
        ]

        return AgentAnalysis(
            agent_name=self.name,
            input_data=data,
            findings=[{
                "contract_vulnerability": result.get("contract_vulnerability"),
                "financial_loss_usd": result.get("financial_loss_usd"),
                "attack_type": result.get("attack_type"),
            }],
            alerts=alerts,
            iocs=[],
            risk_score=self._parse_score(result.get("risk_score")),
            confidence=0.88,
            recommendations=result.get("immediate_actions", []),
            raw_ai_response=response,
        )
