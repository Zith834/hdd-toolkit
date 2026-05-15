import struct

from hdd_firmware_toolkit.firmware.samsung import (
    SamsungFirmwareParser,
    SamsungSection,
    samsung_decode,
)
from hdd_firmware_toolkit.firmware.seagate import SeagateFWLoader
from hdd_firmware_toolkit.firmware.toshiba import ToshibaFirmwareParser
from hdd_firmware_toolkit.firmware.wd import LZHUFDecoder, WDFirmwareParser, WDSection


def test_lzhuf_init():
    dec = LZHUFDecoder()
    assert dec is not None


def test_samsung_decode_nonzero():
    original = b"\x00\x01\x02\x03\xFF\xFE\xFD\xFC"
    encoded = samsung_decode(original)
    assert len(encoded) == len(original)
    assert encoded != original


def test_wd_parser_empty():
    parser = WDFirmwareParser()
    sections = parser.parse(b"")
    assert sections == []


def test_wd_parser_repack_empty():
    result = WDFirmwareParser.repack([])
    assert len(result) > 0


def test_samsung_parser_empty():
    parser = SamsungFirmwareParser()
    sections = parser.parse(b"")
    assert sections == []


def test_seagate_parse_raises_on_empty():
    loader = SeagateFWLoader()
    import pytest
    with pytest.raises(ValueError, match="File too small"):
        loader.parse(b"")


def test_seagate_repack_empty_has_header():
    result = SeagateFWLoader.repack([])
    assert len(result) > 0
    assert result[0:3] == b"LDL"


def test_toshiba_parser_minimal():
    data = struct.pack("<4s4s", b"TEST", b"v1.0")
    data += b"\x00" * 500
    parser = ToshibaFirmwareParser(data)
    summary = parser.summary()
    assert len(summary) > 0


def test_wd_section_dataclass():
    s = WDSection(index=1, base_addr=0x2000, file_offset=512,
                  compressed_size=1024, decompressed_size=2048,
                  checksum=0xABCD, is_loader=False)
    assert s.compressed_size == 1024


def test_samsung_section_dataclass():
    s = SamsungSection(index=2, base_addr=0, offset=256, size=4096)
    assert s.size == 4096
