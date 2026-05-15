import struct
from dataclasses import dataclass


@dataclass
class ToshibaFirmwareImage:
    """Parsed Toshiba firmware image section descriptor."""

    offset: int
    size: int
    load_addr: int
    entry_point: int
    flags: int
    data: bytes


class ToshibaFirmwareParser:
    """
    Toshiba HDD/SSD firmware image parser.
    Toshiba firmware images carry magic 0x544F5348 ('TOSHIBA') or 0x544F4348 ('TOCHA')
    at offset 0, followed by a 0x200-byte header containing NAND configuration tables,
    ARM exception vector base, and encrypted/packed section descriptors.

    Known models: DT01ACAxxx (desktop), MQ01ABBxxx (laptop), HK4R (enterprise SSD),
    TR200 (DRAM-less SSD), XG5/XG6 (NVMe).

    Header structure (common layout -- varies slightly by family):
      [0x000] MAGIC (4 bytes)     -- 'TOSH' or 'TOCH'
      [0x004] Header size (4)     -- typically 0x200
      [0x008] Image version (16)  -- null-terminated string
      [0x018] Section count (4)
      [0x01C] NAND config offset (4)
      [0x020] Section table offset (4)
      [0x024] Encryption flags (4) -- bit 0 = AES-128, bit 1 = AES-256, bit 2 = XOR obfuscation
      [0x028] Checksum type (4)   -- 0=none, 1=CRC32, 2=SHA256
      [0x02C] ARM vector offset (4)
      [0x100] NAND configuration table (variable)
      [0x180] Section descriptors (16 bytes each)

    Sources:
      - INVESTIGATION.md  -- "Dolphin Data Lab -- Toshiba HDD Firmware Structure":
          PCB firmware placement (adaptives/translator/P-list on PCB vs G-list/SMART on platter)
      - INVESTIGATION.md  -- "Reversing the Toshiba NAS HDD firmware updater for Linux":
          ATA 0x92 DOWNLOAD-MICROCODE with subcmd 0x03, 128=512B chunks
      - INVESTIGATION.md  -- "New Screwdriver -- Toshiba 2.5\" SATA HDD PCB teardown":
          Marvell 8816717 + Spansion FL040A005 flash hardware layout
      - INVESTIGATION.md  -- "Equation Group / Kaspersky -- Feb 2015":
          nls_933w.dll confirms NSA targets Toshiba drives in-the-wild
    """

    MAGIC_TOSHIBA = b"TOSH"
    MAGIC_TOCHIBA = b"TOCH"

    @dataclass
    class ToshSection:
        index: int
        name: str
        offset: int
        size: int
        load_addr: int
        entry_point: int
        flags: int
        data: bytes

    def __init__(self, data: bytes):
        self.data = data
        self.magic = data[:4]
        self.header_size = struct.unpack_from("<I", data, 4)[0]
        self.version_str = self._read_str(8, 16)
        self.section_count = struct.unpack_from("<I", data, 0x18)[0]
        self.nand_config_offset = struct.unpack_from("<I", data, 0x1C)[0]
        self.section_table_offset = struct.unpack_from("<I", data, 0x20)[0]
        self.encryption_flags = struct.unpack_from("<I", data, 0x24)[0]
        self.checksum_type = struct.unpack_from("<I", data, 0x28)[0]
        self.arm_vector_offset = struct.unpack_from("<I", data, 0x2C)[0]
        self.sections: list[ToshibaFirmwareParser.ToshSection] = []
        self.nand_config: dict[str, int] = {}
        self._parse_nand_config()
        self._parse_sections()
        self.valid = self.magic in (self.MAGIC_TOSHIBA, self.MAGIC_TOCHIBA)

    def _read_str(self, offset: int, max_len: int) -> str:
        end = self.data.find(b"\x00", offset, offset + max_len)
        if end == -1:
            end = offset + max_len
        return self.data[offset:end].decode("ascii", errors="replace")

    def _parse_nand_config(self):
        off = self.nand_config_offset
        if off < 4 or off + 64 > len(self.data):
            return
        fields = [
            ("pages_per_block", 0),
            ("page_size", 4),
            ("block_count", 8),
            ("planes", 12),
            ("ce_pins", 16),
            ("timing_mode", 20),
            ("ecc_strength", 24),
            ("channel_count", 28),
        ]
        for name, delta in fields:
            val = struct.unpack_from("<I", self.data, off + delta)[0]
            if val != 0xFFFFFFFF:
                self.nand_config[name] = val

    def _parse_sections(self):
        stbl = self.section_table_offset
        if stbl < 4 or stbl >= len(self.data):
            return
        for i in range(min(self.section_count, 32)):
            off = stbl + i * 16
            if off + 16 > len(self.data):
                break
            flags = struct.unpack_from("<I", self.data, off)[0]
            load_addr = struct.unpack_from("<I", self.data, off + 4)[0]
            size = struct.unpack_from("<I", self.data, off + 8)[0]
            entry = struct.unpack_from("<I", self.data, off + 12)[0]
            data_off = (
                struct.unpack_from("<I", self.data, off + 16)[0]
                if off + 20 <= len(self.data)
                else 0
            )
            if size == 0 or data_off == 0:
                continue
            if data_off + size > len(self.data):
                size = len(self.data) - data_off
            raw = self.data[data_off : data_off + size]
            sec = self.ToshSection(
                index=i,
                name=f"sec_{i:02X}",
                offset=data_off,
                size=size,
                load_addr=load_addr,
                entry_point=entry,
                flags=flags,
                data=raw,
            )
            self.sections.append(sec)

    def summary(self) -> str:
        lines = ["Toshiba Firmware Image"]
        lines.append(f"  Magic:         {self.magic!r}")
        lines.append(f"  Version:       {self.version_str}")
        lines.append(f"  Sections:      {len(self.sections)}")
        lines.append(f"  Encryption:    0x{self.encryption_flags:04X}")
        lines.append(f"  Checksum type: {self.checksum_type}")
        cnfg = ", ".join(f"{k}={v}" for k, v in self.nand_config.items())
        lines.append(f"  NAND config:   [{cnfg}]")
        lines.append(f"  ARM vectors:   0x{self.arm_vector_offset:04X}")
        for sec in self.sections:
            lines.append(
                f"    [{sec.index:2d}] 0x{sec.load_addr:08X} "
                f"+{sec.size:>6}  flags=0x{sec.flags:02X} "
                f"entry=0x{sec.entry_point:08X}"
            )
        return "\n".join(lines)
