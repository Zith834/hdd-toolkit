import struct
from dataclasses import dataclass, field


def samsung_decode(data: bytes) -> bytes:
    """
    Reverse the Samsung PM871a / 840 EVO nibble-swap obfuscation.

    Algorithm (from TheMissingManual): per-byte transform on the HIGH nibble only.
    The low nibble is untouched.  Fully reversible (applying it twice is identity).
    """
    buf = bytearray(data)
    for i in range(len(buf)):
        hi = (buf[i] >> 4) & 0xF
        if hi & 1:
            hi >>= 1
        else:
            hi = 0xF - (hi >> 1)
        buf[i] = (buf[i] & 0x0F) | (hi << 4)
    return bytes(buf)


@dataclass
class SamsungSection:
    index: int
    base_addr: int
    offset: int
    size: int
    data: bytes = field(repr=False, default=b"")


class SamsungFirmwareParser:
    """
    Parse Samsung PM871a firmware images.
    Section descriptors appear after an 8KB metadata block.
    Offset and size are in units of 16KB blocks.
    """

    BLOCK_SIZE = 0x4000  # 16 KB
    META_SIZE = 0x2000  # 8  KB
    DESC_STRIDE = 0x10

    def parse(self, data: bytes) -> list[SamsungSection]:
        sections = []
        offset = self.META_SIZE
        index = 0

        while offset + self.DESC_STRIDE <= len(data):
            base_addr, blk_offset, blk_size, _flags = struct.unpack_from("<IIII", data, offset)

            if base_addr == 0 and blk_offset == 0:
                offset += self.DESC_STRIDE
                continue
            if base_addr == 0xFFFFFFFF:
                break

            byte_offset = blk_offset * self.BLOCK_SIZE
            byte_size = blk_size * self.BLOCK_SIZE

            sec_data = data[byte_offset : byte_offset + byte_size]

            sections.append(
                SamsungSection(
                    index=index,
                    base_addr=base_addr,
                    offset=byte_offset,
                    size=byte_size,
                    data=sec_data,
                )
            )

            offset += self.DESC_STRIDE
            index += 1

        return sections
