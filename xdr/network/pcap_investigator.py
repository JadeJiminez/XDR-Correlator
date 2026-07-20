"""
pcap_investigator.py — capture source selection, TCP payload extraction, and
per-packet logging. Delegates indicator scanning to payload_scan.py.
"""

from typing import Optional

from scapy.all import sniff, rdpcap, wrpcap, IP, IPv6, ARP, TCP

from xdr.network.payload_scan import scan_payload
from xdr.core.events import SecurityEvent, Vector
from xdr.core.event_bus import ENGINE


class PcapInvestigator:
    """Chooses between live capture or reading from a pcap file, and
    extracts raw TCP payload bytes per packet for downstream scanning."""

    def __init__(self, pcap_file_dir: Optional[str] = None):
        self.pcap_file_dir = pcap_file_dir

    def capture_type(self) -> str:
        return "file" if self.pcap_file_dir else "live"

    def get_packets(self, live_count: int = 10, save_live_as: str = "live_capture.pcap"):
        if self.pcap_file_dir:
            return rdpcap(self.pcap_file_dir)
        packets = sniff(count=live_count)
        wrpcap(save_live_as, packets)
        return packets

    @staticmethod
    def extract_tcp_payload(packet) -> bytes:
        """Extract raw TCP payload bytes from a packet. Returns b'' if the
        packet has no TCP layer or an empty payload."""
        if packet.haslayer(TCP):
            return bytes(packet[TCP].payload)
        return b""

    def log_packet(
        self,
        packet,
        got_base: Optional[int] = None,
        got_size: Optional[int] = None,
    ) -> None:
        """Print packet metadata, then extract + scan the TCP payload (if any)
        and print any shellcode indicators found."""
        if IP in packet:
            print(f"Source: {packet[IP].src}, Destination: {packet[IP].dst}, Protocol = {packet[IP].proto}")
        elif IPv6 in packet:
            print(f"Source: {packet[IPv6].src}, Destination: {packet[IPv6].dst}, Protocol = {packet[IPv6].nh}")
        elif ARP in packet:
            print(f"Source: {packet[ARP].psrc}, Destination: {packet[ARP].pdst}, Protocol = {packet[ARP].op}")
        else:
            print(packet.summary())

        raw_payload = self.extract_tcp_payload(packet)
        if raw_payload:
            print(f"TCP Payload: {raw_payload}")
            findings = scan_payload(raw_payload, got_base, got_size)
            src_ip= packet[IP].src if IP in packet else "unknown"

            for finding in findings:
                print(f"  [!] {finding}")
                event = SecurityEvent(
                    vector=Vector.NETWORK,
                    event_type = "payload_scan_finding",
                    src = src_ip,
                    severity = 3,
                    metadata = {"finding": finding},
                )
                ENGINE.publish_threadsafe(event)
