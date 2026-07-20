"""
tests/test_payload_scan.py — pytest coverage for xdr.network.payload_scan.scan_payload().

Each test below simulates one recognizable stage or technique from real
shellcode/exploit-delivery payloads, and checks that scan_payload() reports
the finding(s) an analyst would expect (or reports nothing, for the clean
case). Findings are returned as a list of human-readable strings; an empty
list means "no alert."
"""

import struct

import pytest

from xdr.network.payload_scan import scan_payload, NOP_SLED


# A GOT range used across the GOT-pointer tests below, standing in for the
# bounds XdrCorrelator would normally get from ElfParser.get_got_range() at
# startup after parsing the real target binary.
GOT_BASE = 0x4032D0
GOT_SIZE = 0x30  # covers .got + .got.plt for a small dynamically-linked ELF


def test_clean_payload_no_alert():
    """
    Simulates: ordinary, benign network traffic.

    An everyday HTTP request has none of the three indicators (no NOP sled,
    no long repeated-byte run, no address-shaped 8-byte value inside a known
    GOT range). This is the negative control -- scan_payload() must return
    an empty list so normal traffic doesn't generate noisy false-positive
    alerts.
    """
    payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"

    findings = scan_payload(payload, got_base=GOT_BASE, got_size=GOT_SIZE)

    assert findings == []


def test_nop_sled_triggers_alert():
    """
    Simulates: classic buffer-overflow shellcode staging.

    Attackers often can't land a return address precisely, so they pad the
    front of their shellcode with a long run of 0x90 (NOP) instructions --
    a "NOP sled" -- so that landing anywhere in the sled just slides the CPU
    forward into the real payload. Sixteen or more consecutive 0x90 bytes is
    a strong, specific signal of this technique.
    """
    payload = b"\x41" * 20 + NOP_SLED + b"\xcc" * 10

    findings = scan_payload(payload, got_base=GOT_BASE, got_size=GOT_SIZE)

    assert any("NOP sled" in f for f in findings)


def test_repeated_byte_pad_triggers_alert():
    """
    Simulates: heap-spray / alignment padding using a non-NOP filler byte.

    Beyond NOP sleds, exploit payloads (especially heap-spray techniques
    used to groom memory layout before triggering a bug) often pad with a
    single repeated byte that isn't 0x90 -- e.g. a filler value chosen to
    also double as a usable pointer/instruction on some architectures. A run
    of 12+ identical bytes of *any* value is flagged, independent of the
    NOP-sled check.
    """
    payload = b"\x00" * 4 + b"\x41" * 18 + b"\x00" * 4  # 18x 'A', not 0x90

    findings = scan_payload(payload, got_base=GOT_BASE, got_size=GOT_SIZE)

    assert any("Repeated byte run" in f for f in findings)


def test_got_pointer_in_payload_triggers_alert():
    """
    Simulates: a GOT-overwrite / ret2libc-style redirection payload.

    Rather than injecting new code, an attacker who knows the target
    binary's GOT layout (e.g. via ElfParser.get_got_range() at startup) can
    embed a crafted 8-byte little-endian address that points directly into
    that GOT range, to overwrite a function pointer and hijack control flow
    without needing an executable stack. Bounding the check to the real
    target's GOT range (instead of a generic heuristic) turns this into a
    precise, low-false-positive signal.
    """
    target_addr = GOT_BASE + 8  # an address inside the known GOT range
    payload = b"\x41" * 8 + struct.pack("<Q", target_addr) + b"\x42" * 8

    findings = scan_payload(payload, got_base=GOT_BASE, got_size=GOT_SIZE)

    assert any("GOT/pointer" in f for f in findings)


def test_combination_exploit_triggers_all_alerts():
    """
    Simulates: a realistic multi-stage exploit payload.

    Real-world shellcode delivery rarely uses just one technique in
    isolation -- a typical payload might pad for alignment, include a NOP
    sled to tolerate an imprecise jump, and embed a GOT pointer to hijack
    execution once landed. This test builds a payload combining all three
    and checks that scan_payload() reports all three finding categories
    simultaneously, confirming the checks are independent and additive
    rather than short-circuiting on the first match.
    """
    target_addr = GOT_BASE + 16  # inside the known GOT range
    payload = (
        b"\x43" * 14                              # repeated-byte padding/alignment
        + NOP_SLED                                # NOP sled
        + struct.pack("<Q", target_addr)          # embedded GOT pointer
        + b"\x90" * 4                             # trailing filler
    )

    findings = scan_payload(payload, got_base=GOT_BASE, got_size=GOT_SIZE)

    assert any("NOP sled" in f for f in findings)
    assert any("Repeated byte run" in f for f in findings)
    assert any("GOT/pointer" in f for f in findings)
