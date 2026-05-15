import struct
from dataclasses import dataclass, field

from hdd_toolkit.core.utils import warn


class LZHUFDecoder:
    """
    LZHUF decompressor with Western Digital variant constants:
      N         = 4096   (standard = 2048)
      F         = 60     (max match length)
      THRESHOLD = 2
      run_len   = match_len - THRESHOLD   (standard adds THRESHOLD)
    """

    N = 4096
    F = 60
    THRESHOLD = 2
    NIL = N

    def __init__(self):
        self._init_tree()

    def _init_tree(self):
        self.lson = [0] * (self.N + 1)
        self.rson = [0] * (self.N + 257)
        self.dad = [0] * (self.N + 1)

    def decompress(self, data: bytes) -> bytes:
        src = bytearray(data)
        out = bytearray()
        ring = bytearray(b" " * self.N)
        r = self.N - self.F
        si = 0

        flags = 0
        flag_count = 0

        while si < len(src):
            if flag_count == 0:
                if si >= len(src):
                    break
                flags = src[si]
                si += 1
                flag_count = 8

            if flags & 1:
                # Literal byte
                if si >= len(src):
                    break
                c = src[si]
                si += 1
                out.append(c)
                ring[r] = c
                r = (r + 1) & (self.N - 1)
            else:
                # Back reference
                if si + 1 >= len(src):
                    break
                pos = src[si] | ((src[si + 1] & 0xF0) << 4)
                si += 2
                length = (src[si - 1] & 0x0F) + self.THRESHOLD
                for _ in range(length):
                    c = ring[pos & (self.N - 1)]
                    out.append(c)
                    ring[r] = c
                    r = (r + 1) & (self.N - 1)
                    pos = (pos + 1) & (self.N - 1)

            flags >>= 1
            flag_count -= 1

        return bytes(out)


# =============================================================================
# WD firmware image parser
# =============================================================================


@dataclass
class WDSection:
    index: int
    base_addr: int
    file_offset: int
    compressed_size: int
    decompressed_size: int
    checksum: int
    is_loader: bool
    data: bytes = field(repr=False, default=b"")
    decompressed_data: bytes = field(repr=False, default=b"")


class WDFirmwareParser:
    SECTION_HEADER_SIZE = 0x10

    def parse(self, data: bytes) -> list[WDSection]:
        sections = []
        offset = 0
        index = 0

        while offset + self.SECTION_HEADER_SIZE <= len(data):
            base_addr, comp_size, decomp_size, checksum = struct.unpack_from("<IIHH", data, offset)

            if base_addr == 0xFFFFFFFF:
                break  # sentinel

            sec_data = data[
                offset + self.SECTION_HEADER_SIZE : offset + self.SECTION_HEADER_SIZE + comp_size
            ]

            calc_cs = sum(sec_data) & 0xFF
            cs_ok = calc_cs == (checksum & 0xFF)

            sec = WDSection(
                index=index,
                base_addr=base_addr,
                file_offset=offset,
                compressed_size=comp_size,
                decompressed_size=decomp_size,
                checksum=checksum,
                is_loader=(index == 0),
                data=sec_data,
            )

            if index == 0:
                sec.decompressed_data = sec_data  # loader is not compressed
            else:
                try:
                    sec.decompressed_data = LZHUFDecoder().decompress(sec_data)
                except Exception as e:
                    warn(f"Section {index}: decompression failed - {e}")
                    sec.decompressed_data = sec_data

            if not cs_ok:
                warn(
                    f"Section {index}: checksum mismatch "
                    f"(file={checksum:#04x} calc={calc_cs:#04x})"
                )

            sections.append(sec)
            offset += self.SECTION_HEADER_SIZE + comp_size
            index += 1

        return sections

    @staticmethod
    def repack(sections: list[WDSection]) -> bytes:
        """Re-pack sections back into a flat firmware image with updated checksums."""
        out = bytearray()
        for sec in sections:
            cs = sum(sec.data) & 0xFF
            hdr_bytes = struct.pack(
                "<IIHH", sec.base_addr, len(sec.data), sec.decompressed_size, cs
            )
            out += hdr_bytes + sec.data
        out += struct.pack("<I", 0xFFFFFFFF)  # sentinel
        return bytes(out)
