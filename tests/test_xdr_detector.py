"""
test_xdr_detector.py — pytest suite for xdr_detector.py

Covers:
  1. Normal TCP exchange -> no hijack alert, anomaly count stays 0
  2. Crafted impossible SEQ skip -> hijack alert fires
  3. SCTP INIT flood -> flood alert fires once threshold is exceeded

Run with:
    pytest test_xdr_detector.py -v
"""

import pytest
from scapy.all import IP, TCP, SCTP, SCTPChunkInit, Raw

from xdr.network.tcp_detector import TcpHijackDetector
from xdr.network.sctp_detector import SctpFloodDetector


def make_tcp_packet(seq, sport=1234, dport=80, src="10.0.0.1", dst="10.0.0.2",
                     flags="", payload=b""):
    """Build a single TCP/IP packet with a given SEQ and optional payload."""
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    if payload:
        pkt = pkt / Raw(load=payload)
    return pkt


# ---------------------------------------------------------------------------
# 1. Normal TCP exchange — no alert should fire
# ---------------------------------------------------------------------------

def test_normal_tcp_exchange_no_alert(capsys):
    detector = TcpHijackDetector()

    # Each packet's SEQ advances by exactly the previous payload length —
    # textbook legitimate traffic.
    p1 = make_tcp_packet(seq=1000, payload=b"A" * 50)
    p2 = make_tcp_packet(seq=1050, payload=b"B" * 50)
    p3 = make_tcp_packet(seq=1100, payload=b"C" * 50)

    detector.process_packet(p1)  # establishes baseline, no check yet
    detector.process_packet(p2)
    detector.process_packet(p3)

    captured = capsys.readouterr()
    assert "Potential TCP Hijack Detected!" not in captured.out
    assert all(count == 0 for count in detector.anomaly_count.values())

    key = detector.conn_key(p3)
    # Baseline should have advanced to the latest legitimate SEQ.
    assert detector.seq_registry[key] == 1100


# ---------------------------------------------------------------------------
# 2. Crafted impossible SEQ skip — alert should fire
# ---------------------------------------------------------------------------

def test_crafted_seq_skip_triggers_alert(capsys):
    detector = TcpHijackDetector()

    p1 = make_tcp_packet(seq=1000, payload=b"A" * 50)
    # Legitimate next SEQ would be ~1050. Jump far past the threshold instead.
    jumped_seq = 1000 + detector.SEQ_JUMP_THRESHOLD + 500
    p2 = make_tcp_packet(seq=jumped_seq, payload=b"B" * 50)

    detector.process_packet(p1)  # baseline
    detector.process_packet(p2)  # should trigger the anomaly

    captured = capsys.readouterr()
    assert "Potential TCP Hijack Detected!" in captured.out

    key = detector.conn_key(p2)
    assert detector.anomaly_count[key] == 1


# ---------------------------------------------------------------------------
# 3. SCTP INIT flood — alert should fire once past max_init_chunks
# ---------------------------------------------------------------------------

def test_sctp_flood_triggers_alert(capsys):
    max_init = 5
    detector = SctpFloodDetector(max_init_chunks=max_init, window_duration=15)

    src_ip = "192.168.1.50"
    dst_ip = "192.168.1.100"

    # One more than the threshold so the flood condition (count > max) is met.
    for _ in range(max_init + 1):
        pkt = IP(src=src_ip, dst=dst_ip) / SCTP(sport=1000, dport=2000) / SCTPChunkInit()
        detector.process_packet(pkt)

    detector.check_thresholds()

    captured = capsys.readouterr()
    assert "ALERT" in captured.out
    assert src_ip in captured.out
    assert detector.init_chunk_count[src_ip] == max_init + 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])