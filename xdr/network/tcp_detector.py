"""
tcp_detector.py — TCP SEQ-jump / hijack anomaly detection.
"""

import time
from typing import Dict, Tuple

from scapy.all import IP, TCP
from xdr.core.events import SecurityEvent, Vector
from xdr.core.event_bus import ENGINE

ConnKey = Tuple[str, str, int, int]  # (src_ip, dst_ip, src_port, dst_port)


class TcpHijackDetector:
    MAX_SEQ = 2 ** 32
    SEQ_JUMP_THRESHOLD = 100_000  # delta beyond this = flagged

    def __init__(self):
        self.seq_registry: Dict[ConnKey, int] = {}
        self.last_seen_time: Dict[ConnKey, float] = {}
        self.anomaly_count: Dict[ConnKey, int] = {}

    @staticmethod
    def conn_key(pkt) -> ConnKey:
        ip = pkt[IP]
        tcp = pkt[TCP]
        return (ip.src, ip.dst, tcp.sport, tcp.dport)

    @classmethod
    def seq_delta(cls, prev_seq: int, curr_seq: int) -> int:
        """Forward distance from prev_seq to curr_seq, accounting for wraparound."""
        delta = curr_seq - prev_seq
        if delta < 0:
            delta += cls.MAX_SEQ
        return delta

    def process_packet(self, pkt) -> None:
        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return

        key = self.conn_key(pkt)
        tcp = pkt[TCP]
        curr_seq = tcp.seq
        payload_len = len(tcp.payload) if tcp.payload else 0

        if key not in self.seq_registry:
            self.seq_registry[key] = curr_seq
            self.last_seen_time[key] = time.time()
            self.anomaly_count[key] = 0
            return

        prev_seq = self.seq_registry[key]
        delta = self.seq_delta(prev_seq, curr_seq)

        flag_str = str(tcp.flags)
        expected_bump = payload_len
        if "S" in flag_str or "F" in flag_str:
            expected_bump += 1  # SYN/FIN consumes one sequence number

        if delta > self.SEQ_JUMP_THRESHOLD:
            self.anomaly_count[key] = self.anomaly_count.get(key, 0) + 1
            self._flag_hijack(key, pkt, prev_seq, curr_seq, delta, expected_bump)

        # Only advance the baseline on real forward progress. If we updated
        # on every packet, a spoofed/injected SEQ jump would become the new
        # "normal" baseline and mask the next legitimate anomaly.
        if delta >= expected_bump:
            self.seq_registry[key] = curr_seq
            self.last_seen_time[key] = time.time()

    def _flag_hijack(self, key, pkt, prev_seq, curr_seq, delta, expected_bump) -> None:
        src_ip, dst_ip, src_port, dst_port = key
        print("Potential TCP Hijack Detected!")
        print(f"Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"Previous SEQ: {prev_seq}, Current SEQ: {curr_seq}, "
              f"Delta: {delta}, Expected Bump: {expected_bump}")
        print(f"Packet Info: {pkt.summary()}")
        print(f"Timestamp: {time.ctime()}")
        print(f"Anomaly count for this connection: {self.anomaly_count[key]}")
        print("-" * 50)

        event = SecurityEvent(
            vector = Vector.NETWORK,
            event_type="tcp_hijack_seq_anomaly",
            src = f"{src_ip}:{src_port} -> {dst_ip}: {dst_port}",
            severity =4,
            metadata ={
                "prev_seq": prev_seq, "curr_seq": curr_seq, "delta": delta,
                "expected_bump": expected_bump, "anomaly_count": self.anomaly_count[key],
            },
        )
        ENGINE.publish_threadsafe(event)
