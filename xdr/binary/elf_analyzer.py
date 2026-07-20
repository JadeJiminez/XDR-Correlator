"""
ELF header reader / GOT address extractor.

Reads the first 64 bytes of a 64-bit ELF binary, extracts key section-header
fields via struct.unpack_from(), cross-checks them against `readelf -h`,
walks the section header table to locate .got / .got.plt, and cross-checks
those addresses against `readelf -SW`.
"""

import subprocess
import sys
import struct
import re
from typing import Dict, Optional, Tuple

ELF64_HDR_FMT = "<16sHHIQQQIHHHHHH"
HEADER_SIZE = 64
SHENTSIZE = 64  # size of one section header entry in a 64-bit ELF


def read_elf_header(binary_path):
    """Read + unpack the first 64 bytes of a 64-bit ELF header."""
    with open(binary_path, "rb") as f:
        buffer = f.read(HEADER_SIZE)

    if len(buffer) < HEADER_SIZE:
        print("File too small to be valid 64-bit ELF binary")
        sys.exit(1)

    if buffer[:4] != b'\x7fELF':
        print("Error: Not valid ELF binary")
        sys.exit(1)

    fields = struct.unpack_from(ELF64_HDR_FMT, buffer)
    e_shoff = fields[6]
    e_shnum = fields[12]
    e_shstrndx = fields[13]

    return e_shoff, e_shnum, e_shstrndx


def dump_readelf_header(binary_path, out_path="sectionheader.txt"):
    """Save `readelf -h` output to a file for cross-checking."""
    with open(out_path, "w") as f:
        subprocess.run(["readelf", "-h", binary_path], stdout=f, check=True)
    return out_path


def parse_checkelf_file(txt_file_path):
    """Parse `readelf -h` text output for the fields we care about."""
    extracted_fields = {}
    with open(txt_file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue

            key, val = line.split(":", 1)
            key = key.strip()
            val = val.strip()

            if key == "Start of section headers":
                extracted_fields["re_e_shoff"] = int(val.split()[0])
            elif key == "Number of section headers":
                extracted_fields["re_e_shnum"] = int(val.split()[0])
            elif key == "Section header string table index":
                extracted_fields["re_e_shstrndx"] = int(val.split()[0])
    return extracted_fields


def cross_check_header(binary_path, e_shoff, e_shnum, e_shstrndx):
    """Cross-check our parsed values against readelf -h. Exit on mismatch."""
    txt_path = dump_readelf_header(binary_path)
    fields = parse_checkelf_file(txt_path)

    if (fields.get('re_e_shoff') != e_shoff or
            fields.get('re_e_shnum') != e_shnum or
            fields.get('re_e_shstrndx') != e_shstrndx):
        print("Cross check failed. Header field incorrect")
        print(f"  python:  e_shoff={e_shoff}, e_shnum={e_shnum}, e_shstrndx={e_shstrndx}")
        print(f"  readelf: {fields}")
        sys.exit(1)

    print("Cross check passed: header fields match readelf -h")

def _walk_got_section(
            binary_path, e_shoff, e_shnum, e_shstrndx
) -> Dict[str, Optional[Tuple[int, int]]]:
    """Walk the section header table and resolve (sh_addr, sh_size) for .got / .got.plt.
    Internal helper function shared by find_got_addresses() and 
    ELFParser - kept separate so both addr_only and addr+size callers reuse the same logic.
    """
    got_sections: Dict[str, Optional[Tuple[int, int]]] = {".got": None, ".got.plt": None}

    with open(binary_path, "rb") as f:
        # locate the section header string table
        shst_offset = e_shoff + (e_shstrndx * SHENTSIZE)
        f.seek(shst_offset)
        strtab_header = f.read(SHENTSIZE)

        sh_strtab_offset = struct.unpack('<Q', strtab_header[24:32])[0]
        sh_strtab_size = struct.unpack('<Q', strtab_header[32:40])[0]

        f.seek(sh_strtab_offset)
        string_tab_bytes = f.read(sh_strtab_size)

        # walk every section header entry
        f.seek(e_shoff)
        for _ in range(e_shnum):
            entry_data = f.read(SHENTSIZE)
            if len(entry_data) < SHENTSIZE:
                break

            sh_name_index = struct.unpack('<I', entry_data[:4])[0]
            sh_addr = struct.unpack('<Q', entry_data[16:24])[0]
            sh_size = struct.unpack('<Q', entry_data[32:40])[0]

            # resolve null-terminated name from the string table
            name_bytes = bytearray()
            curr_idx = sh_name_index
            while curr_idx < len(string_tab_bytes) and string_tab_bytes[curr_idx] != 0:
                name_bytes.append(string_tab_bytes[curr_idx])
                curr_idx += 1

            section_name = name_bytes.decode('utf-8', errors='ignore')

            if section_name in got_sections:
                got_sections[section_name] = (sh_addr, sh_size)

    return got_sections

def find_got_addresses(binary_path, e_shoff, e_shnum, e_shstrndx):
    """Walk the section header table and resolve .got / .got.plt addresses.
    Kept for backward compatibity (addr-only, same return shape as before)
    Use ElfParser if need section sizes to compute a GOT Range
    """

    got_sections = _walk_got_section(binary_path, e_shoff, e_shnum, e_shstrndx)
    return {name: (info[0] if info else None) for name, info in got_sections.items()}


def parse_gotverify(binary_path, python_results):
    """Cross-check .got / .got.plt addresses against readelf -SW."""
    print("CROSS CHECK WITH READELF -SW")
    try:
        result = subprocess.run(
            ["readelf", "-SW", binary_path],
            capture_output=True, text=True, check=True,
        )
    except FileNotFoundError:
        print("Error: 'readelf' utility is not installed or missing from system PATH.")
        return
    except subprocess.CalledProcessError as e:
        print(f"Error: readelf failed on {binary_path}: {e}")
        return

    for name, py_addr in python_results.items():
        if py_addr is None:
            print(f"{name}: Skipped (Not found by Python script)")
            continue

        pattern = rf"\]\s+{re.escape(name)}\s+\w+\s+([0-9a-fA-F]+)"
        match = re.search(pattern, result.stdout)

        if not match:
            print(f"{name}: Skipped (Not found in readelf -SW output)")
            continue

        readelf_addr_hex = match.group(1).lstrip('0') or '0'
        py_addr_hex = f"{py_addr:x}"
        status = "Match" if readelf_addr_hex == py_addr_hex else "Mismatch"
        print(f"{name}: python=0x{py_addr_hex} readelf=0x{readelf_addr_hex} -> {status}")


def analyze_elf(binary_path):
    """Full pipeline: parse header, cross-check, find GOT addrs, verify."""
    e_shoff, e_shnum, e_shstrndx = read_elf_header(binary_path)
    print(f"e_shoff={e_shoff}, e_shnum={e_shnum}, e_shstrndx={e_shstrndx}")

    cross_check_header(binary_path, e_shoff, e_shnum, e_shstrndx)

    got_addresses = find_got_addresses(binary_path, e_shoff, e_shnum, e_shstrndx)
    print(f"GOT addresses: {got_addresses}")

    parse_gotverify(binary_path, got_addresses)
    return got_addresses


class ElfParser:
    """High-level wrapper around the ELF parsing pipeline for callers (start up)
    that just want GOT bounds for a targery binary
    without dealing with the lower-level header/section-walk functions
    """

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self._got_sections: Optional[Dict[str, Optional[Tuple[int, int]]]] = None

    def parse(self) ->Dict[str, Optional[int]]:
        """Run the full pipeline (header parse + cross-check against readeld -h + GOT section walk
        cross-check against readelf -SW), caching (addr, size) per GOT section. Returns the same 
        addr-only dict shape as analyze_elf()/find_got_addressess() for convienence
        """

        e_shoff, e_shnum, e_shstrndx = read_elf_header(self.binary_path)
        cross_check_header(self.binary_path, e_shoff, e_shnum, e_shstrndx)

        self._got_sections = _walk_got_section(self.binary_path, e_shoff, e_shnum, e_shstrndx)
        got_addresses = {
                name: (info[0] if info else None) for name, info in self._got_sections.items()
        }
        parse_gotverify(self.binary_path, got_addresses)
        return got_addresses
    
    def get_got_range(self) -> Tuple[Optional[int], Optional[int]]:
        """Return (got_base, got_size) spanning every discovered GOT section
        (.got and .got.plt, when both exist), or (None, None) if neither was found
        Parse the binary on first call if not already parsed
        This is the value expeced by scan_payload()'s got_base/got_size parameters,
        so a typical startup sequence is:
        
            elf_parser = ELFParser(target_binary_path)
            got_base, got_size = elf_parser.get_got_range()
        """

        if self._got_sections is None:
            self.parse()

        found = [info for info in self._got_sections.values() if info is not None]
        if not found:
            return None, None
        
        got_base = min(addr for addr, _ in found)
        got_end = max(addr + size for addr, size in found)
        return got_base, got_end - got_base
    
    if __name__ == "__main__":
        if len(sys.argv) < 2:
            print("Error: Please provide binary.")
            sys.exit(1)

        analyze_elf(sys.argv[1])