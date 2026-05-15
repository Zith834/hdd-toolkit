import struct
from dataclasses import dataclass, field

from hdd_firmware_toolkit.core.utils import info, warn


@dataclass
class SeagateLODSection:
    id: int
    offset: int
    size: int
    load_addr: int
    flags: int
    checksum: int
    data: bytes = field(repr=False, default=b"")


class SeagateFWLoader:
    """
    Seagate .lod firmware file parser/repacker.
    .lod files are the standard Seagate firmware update container format,
    used by the F3 architecture (Barracuda, IronWolf, Exos families).

    Format structure (confirmed by Eurecom tools and MalwareTech RE):
      Offset  Size  Field
      ==============================================
      0x000   4     Magic: 0x014C444C  (little-endian, ASCII: 'LD' + '\\x01\\x00')
      0x004   4     Header size (typically 0x30)
      0x008   4     Section count
      0x00C  20     Vendor string (20 bytes, null-padded)
      0x020   N*16  Section descriptors

    Each section descriptor:
      0x00  2     Section ID
      0x02  2     Data offset in file (short form; 0=inline after descriptor)
      0x04  4     Data size (bytes)
      0x08  4     Load address  (ARM Thumb destination in DRAM)
      0x0C  2     Flags
      0x0E  2     Checksum (sum of payload bytes & 0xFFFF)

    Sources:
      - INVESTIGATION.md  -- "seagate_fw_extract.py":
          Eurecom's hdd_firmware_tools confirms MAGIC/structure
      - INVESTIGATION.md  -- "MalwareTech -- Hard Disk Firmware Hacking":
          Multi-core architecture (core 1=debug, core 2=SATA+bootloader)
      - INVESTIGATION.md  -- "HDD Serial Commander":
          Seagate F3 diagnostic UART for low-level firmware ops
    """

    HEADER_SIZE = 32
    DESC_SIZE = 16
    MAGIC = 0x014C444C  # 'LOD\x01' little-endian

    def parse(self, data: bytes) -> list[SeagateLODSection]:
        if len(data) < self.HEADER_SIZE:
            raise ValueError(f"File too small for .lod header ({len(data)} bytes)")

        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != self.MAGIC:
            raise ValueError(f"Bad .lod magic: 0x{magic:08X} (expected 0x{self.MAGIC:08X})")

        header_size = struct.unpack_from("<I", data, 4)[0]
        total_sections = struct.unpack_from("<I", data, 8)[0]
        data[12:32].rstrip(b"\x00").decode("ascii", errors="replace")

        sections = []
        desc_off = header_size if header_size >= self.HEADER_SIZE else self.HEADER_SIZE

        for i in range(total_sections):
            if desc_off + self.DESC_SIZE > len(data):
                warn(f"Section {i}: truncated descriptor at offset 0x{desc_off:X}")
                break

            sec_id, sec_off, sec_size, load_addr, flags, csum = struct.unpack_from(
                "<HHIIHH", data, desc_off
            )

            if sec_size == 0xFFFF or sec_size == 0:
                info(f"Section {sec_id}: skip (size=0/0xFFFF)")
                desc_off += self.DESC_SIZE
                continue

            raw_start = sec_off if sec_off else desc_off + self.DESC_SIZE
            raw_end = raw_start + sec_size

            sec_data = data[raw_start:raw_end] if raw_end <= len(data) else data[raw_start:]
            calc_cs = sum(sec_data) & 0xFFFF
            cs_ok = calc_cs == csum or csum == 0

            sections.append(
                SeagateLODSection(
                    id=i,
                    offset=raw_start,
                    size=sec_size,
                    load_addr=load_addr,
                    flags=flags,
                    checksum=csum,
                    data=sec_data,
                )
            )

            if not cs_ok:
                warn(
                    f"Section {sec_id}: checksum mismatch (file=0x{csum:04X} calc=0x{calc_cs:04X})"
                )

            desc_off += self.DESC_SIZE

        return sections

    @staticmethod
    def repack(sections: list[SeagateLODSection], vendor_str: str = "") -> bytes:
        """Re-pack sections back into a .lod file."""
        header = bytearray(32)
        struct.pack_into("<I", header, 0, SeagateFWLoader.MAGIC)
        struct.pack_into("<I", header, 4, 32)
        struct.pack_into("<I", header, 8, len(sections))
        vendor_bytes = vendor_str.encode()[:20]
        header[12 : 12 + len(vendor_bytes)] = vendor_bytes

        descs = bytearray()
        body = bytearray()
        offset = 32 + len(sections) * SeagateFWLoader.DESC_SIZE

        for sec in sections:
            aligned = (offset + 3) & ~3
            body.extend(b"\x00" * (aligned - offset))
            offset = aligned + len(sec.data)
            descs += struct.pack(
                "<HHIIHH",
                sec.id,
                offset,
                len(sec.data),
                sec.load_addr,
                sec.flags,
                sum(sec.data) & 0xFFFF,
            )
            body += sec.data

        return bytes(header + descs + body)
