"""
stage_map.py maps concrete detector event_type strings to the abstract kill-chain stage labels KillChainCorrelator 
matches against recon, exploit, persist

mapping rationale:
    sctp_init_flood -> recon
    tcpHijack_seq_anomaly -> exploit
    payload_scan_finding -> exploit
    file_created/file modified -> persist
    ebpf_unexpected_bpf_syscall -> persist
"""

from typing import Dict, Optional

STAGE_MAP: Dict[str, str] = {
    "sctp_init_flood": "recon",
    "tcp_hijack_seq_anomaly": "exploit",
    "payload_scan_finding": "exploit",
    "file_created": "persist",
    "file_modified": "persit",
    "ebpf_unexpected_bpf_syscall": "persist",
}

def get_stage(event_type: str) -> Optional[str]:
    """Returns the abstract stage for a given event_type, or None if not mapped"""
    return STAGE_MAP.get(event_type)