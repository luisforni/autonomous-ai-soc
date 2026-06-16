"""Tests for BaseAgent."""
import pytest
from core.base_agent import AgentPriority, AgentStatus


def test_agent_priority_ordering():
    assert AgentPriority.CRITICAL.value > AgentPriority.LOW.value


@pytest.mark.asyncio
async def test_agent_registry():
    from core.agent_registry import registry
    assert registry is not None
