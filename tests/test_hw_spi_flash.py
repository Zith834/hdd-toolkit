from hdd_toolkit.hw.spi_flash import SPIFlashCapture, SPIFlashInfo, SPITransaction


def _make_csv(rows: list[str]) -> str:
    header = "Packet ID,Time [s],Packet type,MOSI,MISO\n"
    return header + "\n".join(rows)


def test_decode_csv_empty():
    info = SPIFlashCapture.decode_csv("Packet ID,Time [s],Packet type,MOSI,MISO\n")
    assert isinstance(info, SPIFlashInfo)
    assert info.firmware_blob == b""


def test_decode_csv_jedec_id():
    csv_text = _make_csv([
        "1,0.0,enable,,",
        "2,0.0,data,0x9F,0x00",
        "3,0.0,data,0x00,0x9D",
        "4,0.0,data,0x00,0x20",
        "5,0.0,data,0x00,0x14",
        "6,0.0,disable,,",
    ])
    info = SPIFlashCapture.decode_csv(csv_text)
    assert info.jedec_id == bytes([0x9D, 0x20, 0x14])
    assert info.manufacturer_id == 0x9D
    assert info.capacity_bytes == 1 * 1024 * 1024


def test_decode_csv_read_data():
    csv_text = _make_csv([
        "1,0.0,enable,,",
        "2,0.0,data,0x03,0x00",
        "3,0.0,data,0x00,0x00",
        "4,0.0,data,0x00,0x00",
        "5,0.0,data,0x00,0xAA",
        "6,0.0,data,0x00,0xBB",
        "7,0.0,disable,,",
    ])
    info = SPIFlashCapture.decode_csv(csv_text)
    assert len(info.firmware_blob) >= 2
    assert info.firmware_blob[0] == 0xAA
    assert info.firmware_blob[1] == 0xBB
    assert info.sha1 != ""


def test_decode_csv_fast_read():
    csv_text = _make_csv([
        "1,0.0,enable,,",
        "2,0.0,data,0x0B,0x00",
        "3,0.0,data,0x00,0x00",
        "4,0.0,data,0x00,0x00",
        "5,0.0,data,0x00,0x00",
        "6,0.0,data,0x00,0x00",
        "7,0.0,data,0x00,0xCC",
        "8,0.0,data,0x00,0xDD",
        "9,0.0,disable,,",
    ])
    info = SPIFlashCapture.decode_csv(csv_text)
    assert len(info.firmware_blob) > 0


def test_parse_jedec_id_issi():
    result = SPIFlashCapture.parse_jedec_id(bytes([0x9D, 0x20, 0x14]))
    assert "ISSI" in result["manufacturer"]
    assert result["capacity_bytes"] == 1 * 1024 * 1024
    assert result["capacity_kb"] == 1024


def test_parse_jedec_id_too_short():
    result = SPIFlashCapture.parse_jedec_id(b"\x9D")
    assert "error" in result


def test_parse_jedec_id_unknown_mfr():
    result = SPIFlashCapture.parse_jedec_id(bytes([0x42, 0x20, 0x14]))
    assert "unknown" in result["manufacturer"]


def test_parse_jedec_id_winbond():
    result = SPIFlashCapture.parse_jedec_id(bytes([0xEF, 0x40, 0x18]))
    assert "Winbond" in result["manufacturer"]
    assert result["capacity_bytes"] == 16 * 1024 * 1024


def test_spi_transaction_opcode():
    tx = SPITransaction(
        index=1,
        mosi_bytes=bytes([0x9F, 0x00, 0x00, 0x00]),
        miso_bytes=bytes([0x00, 0x9D, 0x20, 0x14]),
        bit_count=32,
    )
    assert tx.opcode == 0x9F


def test_spi_transaction_address():
    tx = SPITransaction(
        index=1,
        mosi_bytes=bytes([0x03, 0x00, 0x10, 0x00]),
        miso_bytes=bytes([0x00, 0xAA]),
        bit_count=32,
    )
    assert tx.address == 0x001000


def test_decode_csv_multiple_transactions():
    csv_text = _make_csv([
        "1,0.0,enable,,",
        "2,0.0,data,0x9F,0x00",
        "3,0.0,data,0x00,0x9D",
        "4,0.0,data,0x00,0x20",
        "5,0.0,data,0x00,0x14",
        "6,0.0,disable,,",
        "7,0.1,enable,,",
        "8,0.1,data,0x03,0x00",
        "9,0.1,data,0x00,0x00",
        "10,0.1,data,0x00,0x00",
        "11,0.1,data,0x00,0xFF",
        "12,0.1,disable,,",
    ])
    info = SPIFlashCapture.decode_csv(csv_text)
    assert info.jedec_id == bytes([0x9D, 0x20, 0x14])
    assert len(info.firmware_blob) >= 1
    assert info.firmware_blob[0] == 0xFF
