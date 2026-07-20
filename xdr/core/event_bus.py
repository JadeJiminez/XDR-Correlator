"""
event_bus.py - Correlation Engine is async pub/sub bus backed by an asyncio.Queue. It uses loop.call_soon_threadsafe()
for publish_threadsafe() since detectors run in real OS threads (BCC's poll thread, watchdog's Observer thread), not 
the event loop's own thread
"""

import asyncio
from typing import Optional
from xdr.core.events import SecurityEvent

class CorrelationEngine:
    def __init__(self, maxsize: int =0):
        self.queue: "asyncio.Queue[SecurityEvent]" = asyncio.Queue(maxsize=maxsize)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        self._loop = loop or asyncio.get_running_loop()

    async def publish(self, event: SecurityEvent) -> None:
        await self.queue.put(event)

    async def publish_threadsafe(self, event: SecurityEvent) -> None:
        await self.queue.put(event)

    def publish_threadsafe(self, event: SecurityEvent) -> None:
        if self._loop is None:
            raise RuntimeError(
                "CorrelationEngine.bind_loop() must be called (from inside "
                "the running event loop) before publish_threadsafe() can be used."
            )
        self._loop.call_soon_threadsafe(self.queue.put_nowait, event)

    async def get(self) -> SecurityEvent:
        return await self.queue.get()
    
    def qsize(self) -> int:
        return self.queue.qsize()
    
ENGINE = CorrelationEngine()
