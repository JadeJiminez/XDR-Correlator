"""
payload_scan.py — scans raw TCP payload bytes for shellcode/exploit-delivery
indicators. Kept separate from PcapInvestigator so it can be unit tested and
reused (e.g. by future host-side or correlation rules) independent of scapy
packet objects.
"""

import re
import struct
from typing import List, Optional

NOP_SLED = b"\x90" * 16  # 16-byte NOP sled
REPEATED_BYTE_RUN = re.compile(rb'(.)\1{11,}', re.DOTALL)  # 12+ identical bytes


def scan_payload(
    payload: bytes,
    got_base: Optional[int] = None,
    got_size: Optional[int] = None,
) -> List[str]:
    """Scan raw TCP payload bytes for shellcode/exploit-delivery indicators:
      - NOP sled (b'\\x90' * 16)
      - Long runs of a repeated byte (12+ identical bytes)
      - 8-byte little-endian values that look like GOT/PLT pointers

    got_base/got_size bound what counts as a plausible GOT address if the
    target binary's GOT range is known (e.g. from elf_analyzer.py). If not
    provided, GOT-pointer detection falls back to a generic heuristic:
    non-null, 8-byte aligned, within a typical userspace address range.

    Returns a list of human-readable finding strings. Empty list if the
    payload is clean.
    """
    findings: List[str] = []

    if not payload:
        return findings

    # --- NOP sled detection ---
    start = 0
    while True:
        index = payload.find(NOP_SLED, start)
        if index == -1:
            break
        findings.append(f"NOP sled detected at offset {index}")
        start = index + len(NOP_SLED)

    # --- Long repeated-byte runs (12+ identical bytes) ---
    for match in REPEATED_BYTE_RUN.finditer(payload):
        findings.append(
            f"Repeated byte run: byte={match.group(1)!r}, "
            f"length={match.end() - match.start()}, offset={match.start()}"
        )

    # --- GOT-style pointer scan: little-endian 8-byte chunks ---
    for offset in range(0, len(payload) - 7):
        chunk = payload[offset:offset + 8]
        value = struct.unpack('<Q', chunk)[0]

        if value == 0:
            continue  # skip null pointers

        if got_base is not None and got_size is not None:
            is_candidate = got_base <= value < (got_base + got_size)
        else:
            # generic userspace address range + 8-byte alignment
            is_candidate = (0x400000 <= value <= 0x7fffffffffff) and (offset % 8 == 0)

        if is_candidate:
            findings.append(f"Possible GOT/pointer value {hex(value)} at offset {offset}")

    return findings
