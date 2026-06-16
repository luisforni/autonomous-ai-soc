"""Registro central de todos los agentes del AI-SOC."""

from __future__ import annotations

from typing import Any, Type

import structlog

from core.base_agent import BaseAgent, AgentStatus

logger = structlog.get_logger(__name__)


class AgentRegistry:
    """Registro y gestión centralizada de agentes."""

    def __init__(self) -> None:
        self._agents: dict[str, BaseAgent] = {}
        self._agent_classes: dict[str, Type[BaseAgent]] = {}

    def register_class(self, agent_class: Type[BaseAgent]) -> None:
        self._agent_classes[agent_class.name] = agent_class
        logger.debug("Agent class registered", agent=agent_class.name)

    def register(self, agent: BaseAgent) -> None:
        self._agents[agent.id] = agent
        logger.info("Agent registered", agent=agent.name, id=agent.id[:8])

    def unregister(self, agent_id: str) -> None:
        agent = self._agents.pop(agent_id, None)
        if agent:
            logger.info("Agent unregistered", agent=agent.name)

    def get(self, agent_id: str) -> BaseAgent | None:
        return self._agents.get(agent_id)

    def get_by_name(self, name: str) -> list[BaseAgent]:
        return [a for a in self._agents.values() if a.name == name]

    def get_by_category(self, category: str) -> list[BaseAgent]:
        return [a for a in self._agents.values() if a.category == category]

    def get_active(self) -> list[BaseAgent]:
        return [a for a in self._agents.values() if a.status != AgentStatus.DISABLED]

    def get_all(self) -> list[BaseAgent]:
        return list(self._agents.values())

    def instantiate(self, agent_name: str) -> BaseAgent | None:
        cls = self._agent_classes.get(agent_name)
        if not cls:
            logger.error("Agent class not found", agent=agent_name)
            return None
        agent = cls()
        self.register(agent)
        return agent

    def get_stats(self) -> dict[str, Any]:
        agents = self.get_all()
        return {
            "total": len(agents),
            "active": len(self.get_active()),
            "by_status": {
                status.value: sum(1 for a in agents if a.status == status)
                for status in AgentStatus
            },
            "by_category": {
                cat: len(self.get_by_category(cat))
                for cat in {a.category for a in agents}
            },
            "registered_classes": len(self._agent_classes),
        }

    def list_available(self) -> list[dict[str, Any]]:
        return [
            {
                "name": cls.name,
                "description": cls.description,
                "category": cls.category,
                "priority": cls.priority.name if hasattr(cls.priority, 'name') else str(cls.priority),
                "version": cls.version,
                "tags": cls.tags,
                "status": "idle",
            }
            for cls in self._agent_classes.values()
        ]


registry = AgentRegistry()
