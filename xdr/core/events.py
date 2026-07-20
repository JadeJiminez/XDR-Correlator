"""
events.py - the SecurityEvent record, the shape every detector's alert gets converted into before entering the Correlation Engine
"""

import time
import uuid as uuid_lib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict

class Vector(Enum):
    """Which layer of the stack an event originated from
        Network - xdr/network/* (SctpFloodDetector, TcpHijackDetector, payload_scan)
        Kernel - xdr/host/ebpf_hooks.py (the __sys_bpf kprobe)
        binary - xdr/host/file_watchdog.py (file create/modify/delete/move)
    """

    NETWORK = "network"
    BINARY = "binary"
    KERNEL = "kernel"

@dataclass
class SecurityEvent:
    vector: Vector
    event_type: str
    src: str
    severity: int #1 (lowest) ...5 (highest)
    metadata: Dict[str, Any] = field(default_factory=dict)
    uuid: str = field(default_factory= lambda: str (uuid_lib.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self):
        if not isinstance(self.severity, int) or not (1 <= self.severity <= 5):
            raise ValueError(f"severity must be an int in 1..5, got {self.severity!r}")
        if not isinstance(self.vector, Vector):
            raise TypeError(f"vector must be a Vector enum member, got {self.vector!r}")
