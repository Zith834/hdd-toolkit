import binascii
import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path

from hdd_toolkit.core.utils import ok


@dataclass
class FirmwarePatch:
    """Describes a single binary patch to apply."""

    offset: int
    original: bytes
    replacement: bytes
    description: str = ""


class FirmwarePatcher:
    """
    After patching a firmware image (NOP out a function, redirect a pointer,
    replace a public key, etc.), you MUST fix the image's checksum or the
    drive will reject it on flash.

    Different vendors use different checksumming:
      WD:     SHA-256 over first M-0x200 bytes, stored at offset 0x00=
              Older drives: simple XOR of all DWORDs -- u32 at 0x1FC
      Seagate: Section-level CRC16 (per LOD section descriptor),
               plus an image-level CRC32 at the trailer
      Samsung: Nibble-swap XOR checksum over each overlay module
      Toshiba: Configurable CRC type in header (0=none, 1=CRC32, 2=SHA256)
      Hitachi: CRC16 over each 0x200-byte block in the first N sectors

    Sources:
      - INVESTIGATION.md  -- "seagate_fw_extract.py":
          .lod CRC16 checksum structure (Eurecom hdd_firmware_tools repo)
      - INVESTIGATION.md  -- "Sprite_TM / Jeroen Domburg -- OHM2013":
          fwtool: WD flash read/write via VSCs + SHA256 verification
      - INVESTIGATION.md  -- "MalwareTech -- 2015":
          Hot-patching: must match original checksum or drive rejects patch
      - INVESTIGATION.md  -- "CVE-2024-42642 -- Crucial MX500 (Aug 2024)":
          Signature bypass via DOWNLOAD-MICROCODE offset overflow

    Usage:
        patcher = FirmwarePatcher(fw_bytes)
        patcher.apply_patch(patch)
        patcher.fix_all()  # regenerate all checksums
        patcher.write("patched_firmware.bin")
    """

    def __init__(self, data: bytes, vendor: str = "auto"):
        self.data = bytearray(data)
        self.vendor = vendor
        if vendor == "auto":
            self.vendor = self._detect_vendor()

    def _detect_vendor(self) -> str:
        if len(self.data) < 8:
            return "unknown"
        magics = {
            b"WDC ": "wd",
            b"ST" + bytes([0x00, 0x00]): "seagate",
            b"TOSH": "toshiba",
            b"TOCH": "toshiba",
            b"SAMSUNG": "samsung",
            b"HITACHI": "hitachi",
            bytes.fromhex("014C444C"): "seagate",  # Seagate LOD magic
        }
        for magic, vendor in magics.items():
            if self.data[: len(magic)] == magic:
                return vendor
        return "unknown"

    def apply_patch(self, patch: FirmwarePatch):
        """Apply a single patch, recording original bytes for rollback."""
        end = patch.offset + len(patch.replacement)
        if end > len(self.data):
            raise ValueError(
                f"Patch at 0x{patch.offset:X} overflows image (need {end}, have {len(self.data)})"
            )
        patch.original = bytes(self.data[patch.offset : end])
        self.data[patch.offset : end] = patch.replacement
        ok(
            f"Patched 0x{patch.offset:X}: "
            f"{patch.original.hex()[:16]}= -- {patch.replacement.hex()[:16]}= "
            f"({patch.description})"
        )

    def rollback(self, patch: FirmwarePatch):
        """Undo a previously applied patch."""
        self.data[patch.offset : patch.offset + len(patch.original)] = patch.original
        ok(f"Rolled back 0x{patch.offset:X}")

    def fix_all(self) -> list[str]:
        """
        Scan the image for known checksum locations and fix them.
        Returns a list of fixes applied.
        """
        fixes = []
        if self.vendor == "wd":
            fix = self._fix_wd()
            if fix:
                fixes.append(fix)
        elif self.vendor == "seagate":
            fix = self._fix_seagate_lod()
            if fix:
                fixes.append(fix)
        elif self.vendor == "toshiba":
            fix = self._fix_toshiba()
            if fix:
                fixes.append(fix)
        elif self.vendor == "samsung":
            fix = self._fix_samsung_overlay()
            if fix:
                fixes.append(fix)
        else:
            fixes.append("No known checksum fix for vendor '{self.vendor}'")
        return fixes

    def _fix_wd(self) -> str | None:
        """WD SHA-256 checksum fix."""
        if len(self.data) < 0x200:
            return None
        if len(self.data) > 0x200:
            payload = bytes(self.data[0x200:])
            sha = hashlib.sha256(payload).digest()
            self.data[0x00:0x20] = sha
            return f"WD SHA256 -- 0x000..0x020 (over {len(payload)} bytes after header)"
        return None

    def _fix_seagate_lod(self) -> str | None:
        """Seagate LOD section-level CRC16 fix."""
        if len(self.data) < 8:
            return None
        magic = struct.unpack_from("<I", bytes(self.data[:4]))[0]
        if magic != 0x014C444C:
            return None
        count = struct.unpack_from("<H", bytes(self.data[4:6]))[0]
        hdr_sz = 0x30 if len(self.data) >= 0x30 else len(self.data)
        header = bytes(self.data[:hdr_sz])
        hdr_crc = binascii.crc_hqx(header, 0xFFFF)
        struct.pack_into("<H", self.data, 6, hdr_crc & 0xFFFF)
        fixes = [f"LOD header CRC16 -- 0x0006 = 0x{hdr_crc:04X}"]

        base = hdr_sz
        for i in range(count):
            off = base + i * 16
            if off + 16 > len(self.data):
                break
            sec_hdr = bytes(self.data[off : off + 8])
            sec_crc = binascii.crc_hqx(sec_hdr, 0xFFFF)
            struct.pack_into("<H", self.data, off + 8, sec_crc & 0xFFFF)
            fixes.append(f"  Section {i} CRC16 -- 0x{off + 8:X} = 0x{sec_crc:04X}")
            sec_size = struct.unpack_from("<H", self.data, off + 2)[0]
            data_off = struct.unpack_from("<I", self.data, off + 12)[0]
            if data_off and sec_size and data_off + sec_size <= len(self.data):
                sec_data = bytes(self.data[data_off : data_off + sec_size])
                data_crc = binascii.crc_hqx(sec_data, 0xFFFF)
                struct.pack_into("<H", self.data, off + 10, data_crc & 0xFFFF)
                fixes.append(f"  Section {i} data CRC16 -- 0x{off + 10:X} = 0x{data_crc:04X}")
        return "\n".join(fixes)

    def _fix_toshiba(self) -> str | None:
        """Toshiba configurable checksum fix."""
        if len(self.data) < 0x30:
            return None
        cksum_type = struct.unpack_from("<I", bytes(self.data[0x28:0x2C]))[0]
        if cksum_type == 0:
            return "Toshiba: no checksum (type=0)"
        if cksum_type == 1:
            # CRC32 over entire image after header
            payload = bytes(self.data[0x200:])
            crc = binascii.crc32(payload) & 0xFFFFFFFF
            struct.pack_into("<I", self.data, 0x1F8, crc)
            return f"Toshiba CRC32 -- 0x1F8 = 0x{crc:08X}"
        if cksum_type == 2:
            payload = bytes(self.data[0x200:])
            sha = hashlib.sha256(payload).digest()
            struct.pack_into("32s", self.data, 0x1E0, sha)
            return "Toshiba SHA256 -- 0x1E0"
        return f"Toshiba: unknown checksum type {cksum_type}"

    def _fix_samsung_overlay(self) -> str | None:
        """Samsung overlay module XOR checksum fix."""
        if len(self.data) < 0x10:
            return None
        xor_sum = 0
        for b in bytes(self.data):
            xor_sum ^= b
        # Samsung XOR checksum is stored in the last byte
        self.data[-1] = xor_sum & 0xFF
        # Second pass: fix trailing DWORD XOR pattern (PM871a style)
        if len(self.data) >= 4:
            dw_sum = 0
            for i in range(0, len(self.data) - 4, 4):
                dw = struct.unpack_from("<I", bytes(self.data[i : i + 4]))[0]
                dw_sum ^= dw
            struct.pack_into("<I", self.data, len(self.data) - 4, dw_sum)
            return f"Samsung overlay XOR (byte=0x{xor_sum:02X}, dword=0x{dw_sum:08X})"
        return f"Samsung overlay byte XOR -- last byte = 0x{xor_sum:02X}"

    def write(self, path: str):
        """Write the patched firmware to a file."""
        Path(path).write_bytes(bytes(self.data))
        ok(f"Wrote {len(self.data)} bytes -- {path}")
