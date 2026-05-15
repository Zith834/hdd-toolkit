import struct

from hdd_firmware_toolkit.core.utils import hdr, info, warn
from hdd_firmware_toolkit.hw.jtag import OpenOCDBridge
from hdd_firmware_toolkit.samsung_mex.memory_map import SamsungMEXMap


class SamsungAESInfo:
    """
    Read AES-XTS-256 key slots and encryption ranges from Samsung MEX RAM.
    (TheMissingManual, "Encryption" section)

    !! TIMING WARNING !!
    The firmware zeroes these tables shortly after completing boot initialisation.
    Connect via JTAG immediately after power-on and halt before the zero-out
    runs, or you will only see zeros.

    Key material structure (at ENC_KEY_MAT_ADDR 0x825E14):
        8 slots = stride (~0x50 bytes each):
            [0]       enabled flag (1 = active)
            [4:36]    AES-256 key1  (32 bytes, XTS first key)
            [36:68]   AES-256 key2  (32 bytes, XTS second key)

    Factory default ranges (250 GB model, ENC_RANGES_ADDR 0x800200F4):
        Slot 0x0:  LBA 0x00000000 - 0x1D1C5970  (250 GB user data, XTS)
        Slot 0x0:  LBA 0x1D24F970 - 0xFFFFFFFF  (tail / unused)
        Slot 0xA:  LBA 0x1D1C5970 - 0x1D24F970  (289 MB shadow MBR / system)

    AES engine: 0x20104000  RNG: 0x2050E000 (=32 bytes at a time)
    """

    M = SamsungMEXMap
    SLOTS = 8
    STRIDE = 0x50  # estimated stride between key-slot entries

    def __init__(self, ocd: "OpenOCDBridge"):
        self.ocd = ocd

    def _read_bytes(self, addr: int, size: int) -> bytes:
        n = (size + 3) // 4
        words = self.ocd.read_memory(addr, 32, n)
        return b"".join(struct.pack("<I", w) for w in words)[:size]

    def dump_key_slots(self) -> list[dict]:
        slots = []
        base = self.M.ENC_KEY_MAT_ADDR
        for i in range(self.SLOTS):
            data = self._read_bytes(base + i * self.STRIDE, self.STRIDE)
            enabled = bool(data[0]) if data else False
            key1 = data[4:36] if len(data) >= 36 else b""
            key2 = data[36:68] if len(data) >= 68 else b""
            slots.append(
                {
                    "slot": i,
                    "enabled": enabled,
                    "key1": key1.hex() if enabled else None,
                    "key2": key2.hex() if enabled else None,
                }
            )
        return slots

    def print_aes_info(self):
        hdr("Samsung MEX AES Configuration")
        warn("!! Dump immediately after power-on - firmware zeroes these tables at boot !!")
        self.ocd.halt()
        slots = self.dump_key_slots()
        self.ocd.resume()

        for s in slots:
            if s["enabled"]:
                (s["key1"] or "")[:32] + "="
                (s["key2"] or "")[:32] + "="
            else:
                pass

        info("Factory layout (250 GB):")
        info("  KeySlot 0x0 -- 250 GB user data  (LBA 0x00000000-0x1D1C5970)")
        info("  KeySlot 0xA -- 289 MB shadow MBR (LBA 0x1D1C5970-0x1D24F970)")
        info("  Replace MEX controller freely - keys live in NAND SA, not in chip")
