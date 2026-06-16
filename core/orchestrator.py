"""Orquestador central del AI-SOC — gestiona el ciclo de vida de los agentes."""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any

import structlog

from core.agent_registry import registry
from core.base_agent import BaseAgent, AgentPriority
from core.config import settings
from core.event_bus import event_bus
from core.models import AgentAnalysis, Alert, Incident, IncidentStatus, Severity

logger = structlog.get_logger(__name__)


class Orchestrator:
    """Orquestador central que coordina todos los agentes del AI-SOC."""

    def __init__(self) -> None:
        self._semaphore = asyncio.Semaphore(settings.agent_max_concurrent)
        self._incidents: dict[str, Incident] = {}
        self._alert_queue: asyncio.Queue[Alert] = asyncio.Queue()
        self._running = False
        self._stats = {
            "analyses_dispatched": 0,
            "alerts_processed": 0,
            "incidents_created": 0,
            "incidents_resolved": 0,
        }

    async def start(self) -> None:
        self._running = True
        event_bus.subscribe("alert.new", self._on_alert)
        event_bus.subscribe("event.security", self._on_security_event)
        asyncio.create_task(self._alert_processor())
        logger.info("Orchestrator started")

    async def stop(self) -> None:
        self._running = False
        logger.info("Orchestrator stopped", stats=self._stats)

    async def dispatch(
        self,
        agent: BaseAgent,
        data: dict[str, Any],
        priority: AgentPriority = AgentPriority.MEDIUM,
    ) -> AgentAnalysis:
        """Despacha un análisis a un agente con control de concurrencia."""
        async with self._semaphore:
            self._stats["analyses_dispatched"] += 1
            analysis = await asyncio.wait_for(
                agent.run_analysis(data),
                timeout=settings.agent_timeout_seconds,
            )

            for alert in analysis.alerts:
                await event_bus.publish("alert.new", alert.model_dump())

            return analysis

    async def dispatch_to_category(
        self,
        category: str,
        data: dict[str, Any],
    ) -> list[AgentAnalysis]:
        """Despacha un análisis a todos los agentes de una categoría."""
        agents = registry.get_by_category(category)
        if not agents:
            logger.warning("No agents found for category", category=category)
            return []

        tasks = [self.dispatch(agent, data) for agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        analyses = []
        for result in results:
            if isinstance(result, Exception):
                logger.error("Agent failed", error=str(result))
            else:
                analyses.append(result)

        return analyses

    async def dispatch_all(self, data: dict[str, Any]) -> list[AgentAnalysis]:
        """Despacha un análisis a todos los agentes activos."""
        agents = registry.get_active()
        tasks = [self.dispatch(agent, data) for agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if not isinstance(r, Exception)]

    async def _on_alert(self, event: dict[str, Any]) -> None:
        alert_data = event.get("data", {})
        await self._alert_queue.put(alert_data)

    async def _on_security_event(self, event: dict[str, Any]) -> None:
        data = event.get("data", {})
        severity = data.get("severity", "medium")

        if severity in ("critical", "high"):
            agents = registry.get_active()
            priority_agents = [a for a in agents if a.priority.value <= 2]
            tasks = [self.dispatch(a, data) for a in priority_agents]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _alert_processor(self) -> None:
        while self._running:
            try:
                alert_data = await asyncio.wait_for(self._alert_queue.get(), timeout=1.0)
                await self._process_alert(alert_data)
                self._stats["alerts_processed"] += 1
            except asyncio.TimeoutError:
                continue

    async def _process_alert(self, alert_data: dict[str, Any]) -> None:
        severity = alert_data.get("severity", "medium")

        if severity in ("critical", "high"):
            incident = await self._create_incident_from_alert(alert_data)
            await event_bus.publish("incident.new", incident.model_dump())

    async def _create_incident_from_alert(self, alert_data: dict[str, Any]) -> Incident:
        incident = Incident(
            title=f"Incidente: {alert_data.get('title', 'Sin título')}",
            description=alert_data.get("description", ""),
            severity=Severity(alert_data.get("severity", "medium")),
            status=IncidentStatus.NEW,
            alerts=[alert_data.get("id", "")],
            affected_assets=alert_data.get("affected_assets", []),
            created_at=datetime.utcnow(),
        )
        self._incidents[incident.id] = incident
        self._stats["incidents_created"] += 1
        logger.info("Incident created", incident_id=incident.id, severity=incident.severity)
        return incident

    def get_incidents(self, status: IncidentStatus | None = None) -> list[Incident]:
        incidents = list(self._incidents.values())
        if status:
            incidents = [i for i in incidents if i.status == status]
        return incidents

    def get_stats(self) -> dict[str, Any]:
        return {
            **self._stats,
            "open_incidents": len([
                i for i in self._incidents.values()
                if i.status not in (IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE)
            ]),
            "alert_queue_size": self._alert_queue.qsize(),
            "agents": registry.get_stats(),
        }


orchestrator = Orchestrator()
