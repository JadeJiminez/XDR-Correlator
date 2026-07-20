"""
manual_test_ioc_matcher.py — run analyze_file() against a small, known set
of files and print a report.

Usage (from the project root):
    python3 manual_test_ioc_matcher.py

Expects the 4 sample files to sit in the SAME directory as this script:
    sample_text.txt, sample_image.png, compiled_binary, random_bytes.bin
"""

import os
from xdr.binary.ioc_matcher import analyze_file, ENTROPY_THRESHOLD

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

FILES = [
    "sample_text.txt",
    "sample_image.png",
    "compiled_binary",
    "random_bytes.bin",
]

# Empty IOC set for this test -- none of these files are known-bad, so
# is_known_ioc should read False for all of them. Add a real SHA-256 here
# to test the "known IOC" match path, e.g.:
#   ioc_set = {"<sha256 of a file you want to flag as known-bad>"}
ioc_set = set()

print(f"Entropy threshold: {ENTROPY_THRESHOLD}\n")
print(f"{'File':<20} {'Entropy':>8}  {'High Entropy?':<14} {'Known IOC?':<10} SHA-256 (first 16)")
print("-" * 90)

for filename in FILES:
    path = os.path.join(TEST_DIR, filename)
    if not os.path.exists(path):
        print(f"{filename:<20} MISSING -- expected at {path}")
        continue

    result = analyze_file(path, ioc_set)
    print(
        f"{filename:<20} {result.entropy:>8.4f}  "
        f"{str(result.high_entropy):<14} {str(result.is_known_ioc):<10} "
        f"{result.sha256[:16]}..."
    )
