from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable


class EventBus:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queues: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]] = []
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self.history: list[dict[str, Any]] = []

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.history.append(event)
            queues = list(self._queues)
            listeners = list(self._listeners)
        for loop, queue in queues:
            loop.call_soon_threadsafe(queue.put_nowait, event)
        for listener in listeners:
            listener(event)

    def listen(self, callback: Callable[[dict[str, Any]], None]) -> None:
        with self._lock:
            self._listeners.append(callback)

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        with self._lock:
            self._queues.append((asyncio.get_running_loop(), queue))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._queues = [(l, q) for l, q in self._queues if q is not queue]

    def reset(self) -> None:
        with self._lock:
            self.history.clear()
