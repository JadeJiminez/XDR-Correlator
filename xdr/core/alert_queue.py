"""
alert_queue.py is a shared thread safe alert queue

A single module-level queue that every detector pushes standardized alert dicts into, so anything 
downstream only has to drain one queue instead of polling each detector separately
Schema:
    "type" :        str, 
    "src"  :        str.
    "timestamp":    float,
    "severity" :    str,
"""

import queue
import time
from typing import Optional

ALERT_QUEUE: "queue.Queue[dict]" = queue.Queue()
VALID_SEVERITIES = {"low", "medium", "high", "critical"}

def make_alert(
        alert_type: str,
        src: str,
        severity: str = "medium",
        timestamp: Optional[float] = None,
) -> dict:
    """Build a standard alert dict that does not push anywhere"""
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"severity must be one of {VALID_SEVERITIES}, got {severity!r}")
    return {
        "type": alert_type,
        "src": src,
        "timestamp": timestamp if timestamp is not None else time.time(),
        "severity": severity,
    }

def push_alert(alert_type: str, src: str, severity: str = "medium") -> dict:
    """Put alerts in shared queue and returns the alert dict that was pushed"""
    alert = make_alert(alert_type, src, severity)
    ALERT_QUEUE.put(alert)
    return alert

def drain_all() -> list:
    """Non-blocking: pop everything currently in the queue and return it as a list"""
    alerts = []
    while True:
        try:
            alerts.append(ALERT_QUEUE.get_nowait())
        except queue.Empty:
            break

    return alerts