"""
benchmarks/run_benchmarks.py — measures detection latency, false-positive
rate, and max throughput for the README.
"""

import asyncio
import contextlib
import io
import statistics
import time

from scapy.all import IP, TCP, Raw, rdpcap

from xdr.core.event_bus import CorrelationEngine
from xdr.network.sctp_detector import SctpFloodDetector
from xdr.network.tcp_detector import TcpHijackDetector
from xdr.network.pcap_investigator import PcapInvestigator

import xdr.network.sctp_detector as sctp_mod
import xdr.network.tcp_detector as tcp_mod
import xdr.network.pcap_investigator as pcap_mod


def _swap_engine(engine: CorrelationEngine):
    sctp_mod.ENGINE = engine
    tcp_mod.ENGINE = engine
    pcap_mod.ENGINE = engine


async def measure_latency(pcap_path: str, warmup: int = 0) -> dict:
    engine = CorrelationEngine()
    engine.bind_loop()
    _swap_engine(engine)

    sctp = SctpFloodDetector(max_init_chunks=2)
    tcp = TcpHijackDetector()
    investigator = PcapInvestigator()

    packets = rdpcap(pcap_path)
    latencies_ms = []

    for i, packet in enumerate(packets):
        t0 = time.perf_counter()

        with contextlib.redirect_stdout(io.StringIO()):
            investigator.log_packet(packet)
            sctp.process_packet(packet)
            tcp.process_packet(packet)
            sctp.check_thresholds()

        await asyncio.sleep(0)

        while not engine.queue.empty():
            await engine.get()
            t1 = time.perf_counter()
            if i >= warmup:
                latencies_ms.append((t1 - t0) * 1000)

    if not latencies_ms:
        return {"count": 0}

    return {
        "count": len(latencies_ms),
        "mean_ms": statistics.mean(latencies_ms),
        "median_ms": statistics.median(latencies_ms),
        "p95_ms": sorted(latencies_ms)[int(len(latencies_ms) * 0.95)] if len(latencies_ms) > 1 else latencies_ms[0],
        "max_ms": max(latencies_ms),
        "min_ms": min(latencies_ms),
    }


async def measure_false_positives(benign_pcap_path: str) -> dict:
    engine = CorrelationEngine()
    engine.bind_loop()
    _swap_engine(engine)

    sctp = SctpFloodDetector(max_init_chunks=5)
    tcp = TcpHijackDetector()
    investigator = PcapInvestigator()

    packets = rdpcap(benign_pcap_path)

    with contextlib.redirect_stdout(io.StringIO()):
        for packet in packets:
            investigator.log_packet(packet)
            sctp.process_packet(packet)
            tcp.process_packet(packet)
        sctp.check_thresholds()

    await asyncio.sleep(0)

    false_positives = []
    while not engine.queue.empty():
        event = await engine.get()
        false_positives.append(event)

    total_packets = len(packets)
    fp_count = len(false_positives)

    return {
        "total_packets": total_packets,
        "false_positive_count": fp_count,
        "fp_rate_pct": round((fp_count / total_packets) * 100, 3) if total_packets else 0.0,
        "false_positives": [(e.event_type, e.src) for e in false_positives],
    }


def _make_synthetic_packet(i: int):
    return (
        IP(src=f"10.0.{(i // 250) % 255}.{i % 250}", dst="10.0.0.1")
        / TCP(sport=1000 + (i % 5000), dport=80, seq=1000 + i, flags="A")
        / Raw(load=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    )


async def measure_max_pps(sample_size: int = 20000, sustained_seconds: float = 3.0) -> dict:
    # --- Part A: raw max speed, unpaced ---
    engine = CorrelationEngine()
    engine.bind_loop()
    _swap_engine(engine)

    sctp = SctpFloodDetector(max_init_chunks=999999)
    tcp = TcpHijackDetector()
    investigator = PcapInvestigator()

    packets = [_make_synthetic_packet(i) for i in range(sample_size)]

    start = time.perf_counter()
    with contextlib.redirect_stdout(io.StringIO()):
        for packet in packets:
            investigator.log_packet(packet)
            tcp.process_packet(packet)
            sctp.process_packet(packet)
    elapsed = time.perf_counter() - start

    max_pps = sample_size / elapsed if elapsed > 0 else 0

    # --- Part B: sustained load, checking for backlog growth ---
    engine2 = CorrelationEngine()
    engine2.bind_loop()
    _swap_engine(engine2)

    sctp2 = SctpFloodDetector(max_init_chunks=999999)
    tcp2 = TcpHijackDetector()
    investigator2 = PcapInvestigator()

    drained_b = 0
    stop = False

    async def consumer():
        nonlocal drained_b
        while not stop:
            try:
                await asyncio.wait_for(engine2.get(), timeout=0.05)
                drained_b += 1
            except asyncio.TimeoutError:
                continue

    consumer_task = asyncio.create_task(consumer())

    queue_depth_samples = []
    i = 0
    sustained_start = time.perf_counter()

    with contextlib.redirect_stdout(io.StringIO()):
        while time.perf_counter() - sustained_start < sustained_seconds:
            packet = _make_synthetic_packet(i)
            investigator2.log_packet(packet)
            tcp2.process_packet(packet)
            sctp2.process_packet(packet)
            i += 1
            if i % 500 == 0:
                await asyncio.sleep(0)
                queue_depth_samples.append(engine2.qsize())

    await asyncio.sleep(0.3)
    stop = True
    await consumer_task

    packets_injected_sustained = i
    sustained_actual_pps = packets_injected_sustained / sustained_seconds

    backlog_growing = False
    if len(queue_depth_samples) >= 4:
        front_half = queue_depth_samples[: len(queue_depth_samples) // 2]
        back_half = queue_depth_samples[len(queue_depth_samples) // 2:]
        if statistics.mean(back_half) > statistics.mean(front_half) * 1.5 + 5:
            backlog_growing = True

    return {
        "max_raw_pps": round(max_pps, 1),
        "sample_size": sample_size,
        "elapsed_s": round(elapsed, 4),
        "sustained_seconds": sustained_seconds,
        "sustained_packets_injected": packets_injected_sustained,
        "sustained_actual_pps": round(sustained_actual_pps, 1),
        "sustained_events_drained": drained_b,
        "queue_depth_samples": queue_depth_samples,
        "backlog_growing_under_sustained_load": backlog_growing,
    }


async def main():
    print("=" * 70)
    print("1. DETECTION LATENCY (packet arrival -> SecurityEvent published)")
    print("=" * 70)
    for pcap in [
        "testdata/pcaps/02_nop_sled.pcap",
        "testdata/pcaps/03_repeated_byte_pad.pcap",
        "testdata/pcaps/04_got_pointer.pcap",
        "testdata/pcaps/05_combo_exploit.pcap",
        "testdata/pcaps/06_sctp_init_flood.pcap",
        "testdata/pcaps/07_tcp_hijack.pcap",
    ]:
        stats = await measure_latency(pcap)
        print(f"\n{pcap}")
        if stats["count"] == 0:
            print("  (no events captured -- check pcap/thresholds)")
        else:
            print(f"  events measured : {stats['count']}")
            print(f"  mean latency    : {stats['mean_ms']:.4f} ms")
            print(f"  median latency  : {stats['median_ms']:.4f} ms")
            print(f"  p95 latency     : {stats['p95_ms']:.4f} ms")
            print(f"  min / max       : {stats['min_ms']:.4f} / {stats['max_ms']:.4f} ms")

    print()
    print("=" * 70)
    print("2. FALSE POSITIVE RATE (benign-only traffic)")
    print("=" * 70)
    fp_stats = await measure_false_positives("testdata/pcaps/08_benign_web_traffic.pcap")
    print(f"  total packets      : {fp_stats['total_packets']}")
    print(f"  false positives    : {fp_stats['false_positive_count']}")
    print(f"  FP rate            : {fp_stats['fp_rate_pct']}%")
    if fp_stats["false_positives"]:
        print(f"  FP details         : {fp_stats['false_positives']}")

    print()
    print("=" * 70)
    print("3. MAX THROUGHPUT (unpaced max speed, then sustained-load check)")
    print("=" * 70)
    pps_stats = await measure_max_pps()
    print(f"  Part A - raw max speed:")
    print(f"    {pps_stats['sample_size']} synthetic packets in {pps_stats['elapsed_s']}s")
    print(f"    => {pps_stats['max_raw_pps']} packets/sec (unpaced, single-threaded)")
    print()
    print(f"  Part B - sustained load for {pps_stats['sustained_seconds']}s:")
    print(f"    packets injected     : {pps_stats['sustained_packets_injected']}")
    print(f"    actual rate achieved : {pps_stats['sustained_actual_pps']} packets/sec")
    print(f"    events drained       : {pps_stats['sustained_events_drained']}")
    print(f"    queue depth samples  : {pps_stats['queue_depth_samples']}")
    status = "BACKLOG GREW (consumer fell behind)" if pps_stats["backlog_growing_under_sustained_load"] else "STABLE (no backlog growth)"
    print(f"    result               : {status}")


if __name__ == "__main__":
    asyncio.run(main())
