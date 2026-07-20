"""
correlator.py — orchestrates PcapInvestigator, SctpFloodDetector, and
TcpHijackDetector over a single packet stream (live capture or pcap file).
"""

import time
import argparse
from typing import Optional

from scapy.all import sniff, rdpcap, wrpcap

from xdr.network.pcap_investigator import PcapInvestigator
from xdr.network.sctp_detector import SctpFloodDetector
from xdr.network.tcp_detector import TcpHijackDetector
from xdr.binary.elf_analyzer import ElfParser

class XdrCorrelator:
    def __init__(
        self,
        verbose_log: bool = True,
        max_init_chunks: int = 5,
        window_duration: int = 15,
        seq_jump_threshold: int = 100_000,
        investigator: Optional[PcapInvestigator] = None,
        got_base: Optional[int] = None,
        got_size: Optional[int] = None,
    ):
        self.verbose_log = verbose_log
        self.got_base = got_base
        self.got_size = got_size
        self.investigator = investigator or PcapInvestigator()
        self.sctp_detector = SctpFloodDetector(max_init_chunks, window_duration)
        self.tcp_detector = TcpHijackDetector()
        self.tcp_detector.SEQ_JUMP_THRESHOLD = seq_jump_threshold
        self.window_duration = window_duration

    def process_packet(self, packet) -> None:
        if self.verbose_log:
            self.investigator.log_packet(packet, got_base=self.got_base, got_size=self.got_size)
        self.sctp_detector.process_packet(packet)
        self.tcp_detector.process_packet(packet)

    def run_on_pcap(self, path: str) -> None:
        packets = rdpcap(path)
        for packet in packets:
            self.process_packet(packet)
        self.sctp_detector.check_thresholds()

    def run_live(self, iface: str = None) -> None:
        print(f"Starting live capture (window = {self.window_duration}s). Ctrl+C to stop.")
        try:
            while True:
                start = time.perf_counter()
                packets = sniff(iface=iface, timeout=self.window_duration, filter="tcp or sctp")
                if packets:
                    wrpcap("live_capture.pcap", packets, append=True)
                    for packet in packets:
                        self.process_packet(packet)
                    self.sctp_detector.check_thresholds()
                self.sctp_detector.reset_window()
                end = time.perf_counter()
                print(f"[window closed in {end - start:.2f}s, {len(packets)} packets]")
        except KeyboardInterrupt:
            print("\nCapture stopped.")


def main():
    parser = argparse.ArgumentParser(description="XDR-Correlator combined detector")
    parser.add_argument("pcap_file", nargs="?", default=None,
                         help="Path to a pcap file to analyze (omit for live capture)")
    parser.add_argument("--iface", default=None, help="Interface for live capture")
    parser.add_argument("--window", type=int, default=15, help="Live capture window in seconds")
    parser.add_argument("--max-init", type=int, default=5, help="INIT chunk flood threshold")
    parser.add_argument("--seq-threshold", type=int, default=100_000, help="SEQ jump threshold")
    parser.add_argument("--quiet", action="store_true", help="Suppress per-packet log lines")
    parser.add_argument("--target-binary", default=None,
                        help = "Path to the ELF binary being defended. If given, its .got/.got.plt" 
                            "range is parsed at startup and used to bound scan_payload()'s "
                            "GOT-pointer detection instead of the generic userspace heuristic",
                            )
    args = parser.parse_args()

    investigator = PcapInvestigator(args.pcap_file)

    #Parse the target binary's GOT range once at startup, so DPI's
    #scan_payload() can flag payload bytes that point specifically into
    # *this* binary's GOT rather than relying on a genric address-range guess
    
    got_base, got_size = None, None
    if args.target_binary:
        elf_parser = ElfParser(args.target_binary)
        got_base, got_size = elf_parser.get_got_range()
        if got_base is not None:
            print(
                f"[startup] Parsed GOT range from {args.target_binary}: "
                f"base=0x{got_base:x} size =0x{got_size:x}"
            )
        else:
            print(
                f"[startup] No .got/.got.plt sections found in {args.target_binary}; "
                f"scan_payload() will fall back to the generic heuristic"
            )

    correlator = XdrCorrelator(
        verbose_log=not args.quiet,
        max_init_chunks=args.max_init,
        window_duration=args.window,
        seq_jump_threshold=args.seq_threshold,
        investigator=investigator,
        got_base= got_base,
        got_size = got_size,
    )

    if investigator.capture_type() == "file":
        correlator.run_on_pcap(args.pcap_file)
    else:
        correlator.run_live(iface=args.iface)


if __name__ == "__main__":
    main()
