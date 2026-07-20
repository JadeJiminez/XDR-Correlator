"""
kill_chain_rules.py — sliding-window kill-chain correlation.
"""

import time
import json
from collections import defaultdict, deque
from typing import Awaitable, Callable, Dict, Optional, Set

from xdr.core.events import SecurityEvent
from xdr.correlation.stage_map import get_stage


class KillChainCorrelator:
    def __init__(
        self,
        window_duration: float = 300.0,
        on_incident: Optional[Callable[[str], Awaitable[None]]] = None,
    ):
        self.window_duration = window_duration
        self._window: Dict[str, deque] = defaultdict(deque)
        self.REQUIRED_STAGES: Set[str] = {"recon", "exploit", "persist"}
        self._on_incident = on_incident

    async def add_event(self, event: SecurityEvent) -> None:
        self._window[event.src].append(event)
        self._prune_window(event.src)

        if self._evaluate_kill_chain(event.src):
            await self._escalate(event.src)

    def _prune_window(self, src_ip: str) -> None:
        cutoff_time = time.time() - self.window_duration
        events_deque = self._window[src_ip]

        while events_deque and events_deque[0].timestamp < cutoff_time:
            events_deque.popleft()

        if not events_deque:
            del self._window[src_ip]

    def _evaluate_kill_chain(self, src_ip: str) -> bool:
        if src_ip not in self._window:
            return False

        present_stages = {
            get_stage(event.event_type) for event in self._window[src_ip]
        }
        present_stages.discard(None)
        return self.REQUIRED_STAGES.issubset(present_stages)

    async def _escalate(self, src_ip: str) -> None:
        correlated_events = sorted(self._window[src_ip], key=lambda e: e.timestamp)

        total_severity = sum(e.severity for e in correlated_events)
        max_severity = max((e.severity for e in correlated_events), default=1)

        incident_report = {
            "incident_type": "correlated_apt_kill_chain",
            "source_ip": src_ip,
            "correlation_window_seconds": self.window_duration,
            "generated_at": time.time(),
            "summary": {
                "total_events_involved": len(correlated_events),
                "max_event_severity": max_severity,
                "calculated_risk_score": round(
                    (total_severity / (len(correlated_events) * 5)) * 100, 2
                ),
            },
            "timeline": [
                {
                    "uuid": event.uuid,
                    "timestamp": event.timestamp,
                    "vector": event.vector.value,
                    "event_type": event.event_type,
                    "severity": event.severity,
                    "metadata": event.metadata,
                }
                for event in correlated_events
            ],
        }

        serialized_report = json.dumps(incident_report, indent=2)
        await self._dispatch_incident(serialized_report)

    async def _dispatch_incident(self, report_json: str) -> None:
        print(f"[!] INCIDENT ESCALATION GENERATED:\n{report_json}")
        if self._on_incident is not None:
            await self._on_incident(report_json)
