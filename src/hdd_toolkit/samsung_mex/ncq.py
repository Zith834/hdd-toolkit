import struct
from enum import IntEnum
from typing import ClassVar

from hdd_toolkit.core.utils import hdr, ok, warn
from hdd_toolkit.hw.jtag import OpenOCDBridge
from hdd_toolkit.samsung_mex.memory_map import SamsungMEXMap


class ATACmd(IntEnum):
    READ_DMA_EXT = 0x25  # LBA48 read - most common SATA read
    WRITE_DMA_EXT = 0x35  # LBA48 write
    DOWNLOAD_MICRO = 0x92  # firmware update (Download Microcode)
    SMART = 0xB0  # SMART command set


class SamsungNCQParser:
    """
    Parse the 33 NCQ (Native Command Queuing) request buffers at 0x00800C00.

    From TheMissingManual:
        33 slots = 16 bytes; slots are at NCQ_BASE + slot_index = 0x10.
        Byte 3 of each slot = ATA command byte.
        Bytes 4-9 = 48-bit LBA (little-endian).

    BUG NOTE: the firmware compares < 32 but then acts, writing a 33rd slot
    (index 32) that may overflow into adjacent data at 0x00800E20.
    """

    M = SamsungMEXMap

    KNOWN_CMDS: ClassVar[dict[ATACmd, str]] = {
        ATACmd.READ_DMA_EXT: "READ DMA EXT (LBA48)",
        ATACmd.WRITE_DMA_EXT: "WRITE DMA EXT (LBA48)",
        ATACmd.DOWNLOAD_MICRO: "DOWNLOAD MICROCODE (fw update)",
        ATACmd.SMART: "SMART",
    }

    def __init__(self, ocd: "OpenOCDBridge"):
        self.ocd = ocd

    def dump(self) -> list[dict]:
        self.ocd.halt()
        slots = []
        for i in range(self.M.NCQ_SLOTS):
            addr = self.M.NCQ_BASE + i * self.M.NCQ_SLOT_SIZE
            words = self.ocd.read_memory(addr, 32, 4)  # 4 = 32-bit = 16 bytes
            raw = b"".join(struct.pack("<I", w) for w in words)
            cmd = raw[self.M.NCQ_CMD_OFFSET] if len(raw) > self.M.NCQ_CMD_OFFSET else 0
            # 48-bit LBA at offset 4 (little-endian, 6 bytes)
            lba_bytes = raw[self.M.NCQ_LBA_OFFSET : self.M.NCQ_LBA_OFFSET + 6]
            lba = int.from_bytes(lba_bytes.ljust(8, b"\x00"), "little")
            slots.append(
                {
                    "slot": i,
                    "addr": addr,
                    "raw": raw.hex(" "),
                    "cmd": cmd,
                    "cmd_str": self.KNOWN_CMDS.get(cmd, f"0x{cmd:02X}"),
                    "lba": lba,
                    "active": cmd != 0,
                }
            )
        self.ocd.resume()
        return slots

    def print_slots(self):
        hdr("Samsung MEX NCQ Buffer Dump  (0x00800C00)")
        slots = self.dump()
        active = sum(1 for s in slots if s["active"])
        for s in slots:
            "  =" if s["active"] else ""
        ok(f"{active} active slot(s) of {self.M.NCQ_SLOTS} total")
        if self.M.NCQ_SLOTS == 33:
            warn(
                "Off-by-one: slot 32 may overwrite memory at "
                f"0x{self.M.NCQ_BASE + 32 * self.M.NCQ_SLOT_SIZE:08X}"
            )
