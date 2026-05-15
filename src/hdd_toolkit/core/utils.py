"""Utility functions for the HDD firmware hacking toolkit."""

import struct
import sys

# Colour helpers (no external deps)

def _c(code: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def ok(msg):
    print(f"\033[32m[+] {msg}\033[0m")


def info(msg):
    print(f"[*] {msg}")


def warn(msg):
    print(f"\033[33m[!] {msg}\033[0m")


def err(msg):
    print(f"\033[31m[-] {msg}\033[0m", file=sys.stderr)


def hdr(msg):
    print(f"\033[36m=== {msg} ===\033[0m")


def hexdump(data: bytes, addr: int = 0, width: int = 16) -> str:
    lines = []
    hex_w = width * 3 - 1
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"  {addr + i:08X}  {hex_part:<{hex_w}}  {ascii_part}")
    return "\n".join(lines)


def find_arm_function_tables(data: bytes, base_addr: int = 0, min_entries: int = 4) -> list[int]:
    """
    Heuristic scan for ARM function pointer tables.
    Looks for runs of 4-byte values that all fall in plausible code regions.
    """
    hits = []
    size = len(data)
    for i in range(0, size - min_entries * 4, 4):
        run = 0
        for j in range(min_entries):
            if i + j * 4 + 4 > size:
                break
            val = struct.unpack_from("<I", data, i + j * 4)[0]
            if val & 1 and 0x1000 <= (val & ~1) < 0xFFFF0000:
                run += 1
            else:
                break
        if run >= min_entries:
            hits.append(base_addr + i)
    return hits


def scan_strings(data: bytes, min_len: int = 5) -> list[tuple[int, str]]:
    """Extract printable ASCII strings from firmware."""
    result = []
    current = []
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b < 0x7F:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append((start, "".join(current)))
            current = []
    return result


def diff_firmware(a: bytes, b: bytes) -> list[tuple[int, bytes, bytes]]:
    """Return list of (offset, old_bytes, new_bytes) for differing regions."""
    diffs = []
    i, n = 0, min(len(a), len(b))
    while i < n:
        if a[i] != b[i]:
            j = i
            while j < n and a[j] != b[j]:
                j += 1
            diffs.append((i, a[i:j], b[i:j]))
            i = j
        else:
            i += 1
    if len(a) != len(b):
        max(len(a), len(b)) - n
        diffs.append((n, b"" if len(a) < len(b) else a[n:], b"" if len(b) < len(a) else b[n:]))
    return diffs


def _hex_dump(data: bytes, width: int = 16) -> str:
    """Format a hex dump similar to xxd."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)
