"""
sctp_detector.py — SCTP INIT-chunk flood detection.
"""

from collections import defaultdict
from typing import Dict

from scapy.all import IP, Raw, SCTPChunkInit
from xdr.core.events import SecurityEvent, Vector
from xdr.core.event_bus import ENGINE


class SctpFloodDetector:
    ALERT = "ALERT: Potential SCTP Flood Attack Detected! Excessive INIT chunks from source IP."

    def __init__(self, max_init_chunks: int = 5, window_duration: int = 15):
        self.max_init_chunks = max_init_chunks
        self.window_duration = window_duration
        self.init_chunk_count: Dict[str, int] = defaultdict(int)

    def process_packet(self, packet) -> None:
        if not packet.haslayer(IP):
            return
        if packet.haslayer(SCTPChunkInit):
            self.init_chunk_count[packet[IP].src] += 1
        elif packet.haslayer(Raw) and packet[IP].proto == 132:  # SCTP protocol number
            sctp_payload = bytes(packet[Raw].load)
            if len(sctp_payload) >= 13 and sctp_payload[12] == 1:  # INIT chunk type
                self.init_chunk_count[packet[IP].src] += 1

    def check_thresholds(self) -> None:
        for src_ip, count in self.init_chunk_count.items():
            if count > self.max_init_chunks:
                print(self.ALERT)
                print(f"Source IP: {src_ip}, INIT Chunk Count: {count}")

                event = SecurityEvent(
                    vector = Vector.NETWORK,
                    event_type = "sctp_init_flood",
                    src = src_ip,
                    severity =4,
                    metadata = {"init_chunk_count": count, "threshold": self.max_init_chunks},
                )
                ENGINE.publish_threadsafe(event)

    def reset_window(self) -> None:
        self.init_chunk_count = defaultdict(int)
