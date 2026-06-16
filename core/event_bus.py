"""Event Bus del AI-SOC — gestión de eventos asíncronos."""

from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from datetime import datetime
from typing import Any, Callable, Coroutine

import structlog

logger = structlog.get_logger(__name__)

HandlerType = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class EventBus:
    """Bus de eventos asíncronos para comunicación entre agentes."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[HandlerType]] = defaultdict(list)
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10000)
        self._running = False
        self._stats = {
            "published": 0,
            "processed": 0,
            "failed": 0,
            "dropped": 0,
        }

    def subscribe(self, event_type: str, handler: HandlerType) -> None:
        self._handlers[event_type].append(handler)
        logger.debug("Handler subscribed", event_type=event_type, handler=handler.__name__)

    def unsubscribe(self, event_type: str, handler: HandlerType) -> None:
        self._handlers[event_type] = [
            h for h in self._handlers[event_type] if h != handler
        ]

    async def publish(self, event_type: str, data: dict[str, Any]) -> None:
        event = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            self._queue.put_nowait(event)
            self._stats["published"] += 1
        except asyncio.QueueFull:
            self._stats["dropped"] += 1
            logger.warning("Event queue full, dropping event", event_type=event_type)

    async def start(self) -> None:
        self._running = True
        logger.info("EventBus started")
        await self._process_loop()

    async def stop(self) -> None:
        self._running = False
        logger.info("EventBus stopped", stats=self._stats)

    async def _process_loop(self) -> None:
        while self._running:
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=1.0)
                await self._dispatch(event)
                self._queue.task_done()
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("Event processing error", error=str(e))

    async def _dispatch(self, event: dict[str, Any]) -> None:
        event_type = event["type"]
        handlers = self._handlers.get(event_type, []) + self._handlers.get("*", [])

        if not handlers:
            return

        tasks = [asyncio.create_task(h(event)) for h in handlers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self._stats["failed"] += 1
                logger.error("Handler failed", error=str(result))
            else:
                self._stats["processed"] += 1

    def get_stats(self) -> dict[str, Any]:
        return {**self._stats, "queue_size": self._queue.qsize()}


event_bus = EventBus()
