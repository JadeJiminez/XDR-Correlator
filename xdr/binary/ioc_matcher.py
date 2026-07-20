""" ioc_matcher.py - SHA-256 IOC matching + Shannon entropy scoring for files.

    Used by xdr/host/file_watchdog.py: when a new or modified file is observed
    analyze_file() hashes it against a local set of known-bad SHA-256 hashes and
    scores its Shannon entropy to flag likely packed/encrypted/compressed content
    (a common trait of malware droppers, randsomeware payloads, and obfuscated 
    shellcode staged a disk).
    
"""

import hashlib
import math
from collections import Counter
from dataclasses import dataclass
from typing import Set

#Plain test sits 4-5, well formed exectuable/DLLs sit 5.5-6.5, and packed/encrypted/
#compressed data pushes toward the theoretical max of 8. 7.2 is a common practical 
#cutoff
ENTROPY_THRESHOLD = 7.2

@dataclass
class FileAnalysisResults:
    path: str
    sha256: str
    entropy: float
    is_known_ioc: bool
    high_entropy: bool

def shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a byte string, in bits per byte
        H = -sum (p_i * log2(p_i)) over each distinct byte value 0-255, where p_i is 
        that byte's frequency in the data. Range from 0 (every byte identical) to 8 
        (every byte value equally likely -- maximum information, characteristic of 
        random/encrypted/compressed data)
        """
    if not data:
        return 0.0
    
    counts= Counter(data)
    length = len(data)

    entropy = 0.0
    for count in counts.values():
        p = count/length
        entropy -=p*math.log2(p)

    return entropy

def sha256_of_file(path: str, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file, reading in chunks so large files don't need
        to be loaded fully into memory just to hash them."""
    
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def analyze_file(
        path: str,
        ioc_hashes: Set[str],
        entropy_threshold: float = ENTROPY_THRESHOLD,
) -> FileAnalysisResults:
    """
    Analyze a single file for IOC/entropy indicators
    
    Compute thefile's SHA-256 and checks it against a local set of known malicious hashes (ioc_hashes)
    eg loaded from a threat-intel feed
    
    Compute the file's Shannon Entropy and flags it if it meets/exceeds entropy_threshold
    """
    
    digest = sha256_of_file(path)
    with open(path, "rb") as f:
        data = f.read()
    entropy = shannon_entropy(data)

    return FileAnalysisResults(
        path = path,
        sha256=digest,
        entropy=entropy,
        is_known_ioc= digest in ioc_hashes,
        high_entropy= entropy>= entropy_threshold,
    )