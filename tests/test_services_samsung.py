from unittest.mock import MagicMock, patch

import pytest

from hdd_toolkit.ata.commands import ATASecurityCommands, SAMSUNG_840_EVO_FW_HISTORY
from hdd_toolkit.samsung_mex.flash import SamsungFlashChannel
from hdd_toolkit.samsung_mex.memory_map import SamsungFlashCmd, SamsungMEXMap


def test_mex_map_constants():
    assert SamsungMEXMap.ATCM_BASE == 0x00000000
    assert SamsungMEXMap.BTCM_BASE == 0x00800000
    assert SamsungMEXMap.NCQ_BASE == 0x00800C00
    assert SamsungMEXMap.NCQ_SLOTS == 33
    assert SamsungMEXMap.GPIO_SAFE_MODE == (1 << 17)
    assert SamsungMEXMap.DMA_BASE == 0x10010060
    assert SamsungMEXMap.DMA_SATA_WINDOW == 0x85833000
    assert SamsungMEXMap.AES_BASE == 0x20104000
    assert SamsungMEXMap.UART_BAUD == 115200
    assert SamsungMEXMap.JTAG_KNOWN_IDCODE == 0x4BA00477


def test_mex_map_flash_channels():
    assert len(SamsungMEXMap.FLASH_CH_ALL) == 8
    assert SamsungMEXMap.FLASH_CH_ALL[4] == 0x204C0000


def test_samsung_fw_history():
    assert len(SAMSUNG_840_EVO_FW_HISTORY) >= 4
    versions = [entry[0] for entry in SAMSUNG_840_EVO_FW_HISTORY]
    assert "EXT0DB6Q" in versions


# == ATASecurityCommands.parse_security_status ================================


def test_parse_security_status_empty():
    result = ATASecurityCommands.parse_security_status(b"")
    assert result == {}


def test_parse_security_status_short():
    result = ATASecurityCommands.parse_security_status(b"\x00" * 10)
    assert result == {}


def test_parse_security_status_all_zero():
    data = b"\x00" * 512
    result = ATASecurityCommands.parse_security_status(data)
    assert result["supported"] is False
    assert result["enabled"] is False
    assert result["locked"] is False
    assert result["frozen"] is False
    assert result["count_expired"] is False
    assert result["enhanced_erase_supported"] is False
    assert result["level"] == "high"


def test_parse_security_status_frozen_bit():
    import struct
    data = bytearray(512)
    struct.pack_into("<H", data, 256, 0x0008)
    result = ATASecurityCommands.parse_security_status(bytes(data))
    assert result["frozen"] is True
    assert result["locked"] is False


def test_parse_security_status_enabled_locked():
    import struct
    data = bytearray(512)
    struct.pack_into("<H", data, 256, 0x0007)
    result = ATASecurityCommands.parse_security_status(bytes(data))
    assert result["supported"] is True
    assert result["enabled"] is True
    assert result["locked"] is True


def test_parse_security_status_maximum_level():
    import struct
    data = bytearray(512)
    struct.pack_into("<H", data, 256, 0x0101)
    result = ATASecurityCommands.parse_security_status(bytes(data))
    assert result["level"] == "maximum"
    assert result["supported"] is True


# == SamsungFlashChannel ======================================================


def _mock_ocd():
    ocd = MagicMock()
    ocd.read_memory.return_value = [0]
    return ocd


def test_flash_channel_invalid_channel():
    ocd = _mock_ocd()
    with pytest.raises(ValueError):
        SamsungFlashChannel(ocd, 8)
    with pytest.raises(ValueError):
        SamsungFlashChannel(ocd, -1)


def test_flash_channel_base_address():
    ocd = _mock_ocd()
    ch0 = SamsungFlashChannel(ocd, 0)
    assert ch0._ch_base == SamsungMEXMap.FLASH_CH_MEX2[0]
    ch4 = SamsungFlashChannel(ocd, 4)
    assert ch4._ch_base == SamsungMEXMap.FLASH_CH_MEX3[0]
    ch7 = SamsungFlashChannel(ocd, 7)
    assert ch7._ch_base == SamsungMEXMap.FLASH_CH_MEX3[3]


def test_flash_channel_fch_offset():
    ocd = _mock_ocd()
    ch = SamsungFlashChannel(ocd, 0)
    assert ch._fch(SamsungMEXMap.FCH_CMD) == SamsungMEXMap.FLASH_CH_MEX2[0] + SamsungMEXMap.FCH_CMD
    assert ch._fch(SamsungMEXMap.FCH_PBPN) == SamsungMEXMap.FLASH_CH_MEX2[0] + SamsungMEXMap.FCH_PBPN


def test_flash_channel_read_page_calls_ocd():
    ocd = _mock_ocd()
    ocd.read_memory.return_value = [0]
    ch = SamsungFlashChannel(ocd, 0)
    with patch("time.time", side_effect=[0, 0, 10]):
        ch.read_page(0x100, 0x05)
    ocd.halt.assert_called_once()
    ocd.resume.assert_called_once()
    assert ocd.cmd.call_count >= 6


def test_flash_channel_write_page_calls_ocd():
    ocd = _mock_ocd()
    ocd.read_memory.return_value = [0]
    ch = SamsungFlashChannel(ocd, 1)
    with patch("time.time", side_effect=[0, 0, 10]):
        ch.write_page(0x200, 0x01, mem_addr=0x804E8200)
    ocd.halt.assert_called()
    ocd.resume.assert_called()
    assert ocd.cmd.called


def test_flash_channel_erase_block_calls_ocd():
    ocd = _mock_ocd()
    ocd.read_memory.return_value = [0]
    ch = SamsungFlashChannel(ocd, 2)
    with patch("time.time", side_effect=[0, 0, 10]):
        ch.erase_block(0x50)
    ocd.halt.assert_called()
    assert ocd.cmd.called


def test_flash_channel_integrity_ok():
    ocd = _mock_ocd()
    ocd.read_memory.side_effect = [
        [0],
        [SamsungMEXMap.FLASH_INTEGRITY_OK],
    ]
    ch = SamsungFlashChannel(ocd, 3)
    with patch("time.time", side_effect=[0, 0, 10]):
        result = ch.check_integrity()
    assert result is True


def test_flash_channel_integrity_fail():
    ocd = _mock_ocd()
    ocd.read_memory.side_effect = [
        [0],
        [0x00],
    ]
    ch = SamsungFlashChannel(ocd, 3)
    with patch("time.time", side_effect=[0, 0, 10]):
        result = ch.check_integrity()
    assert result is False


def test_flash_channel_dispatch_value():
    ocd = _mock_ocd()
    ch = SamsungFlashChannel(ocd, 5)
    ch._set_dispatch(SamsungFlashChannel.ZONE_CHIP1, SamsungFlashChannel.OP_READ)
    expected_dispatch = 0x3F | (5 << 10)
    from unittest.mock import call
    ocd.cmd.assert_any_call(f"mww 0x{SamsungMEXMap.FLASH_DISPATCH:08X} 0x{expected_dispatch:08X}")


def test_flash_channel_read_sa_page():
    ocd = _mock_ocd()
    ocd.read_memory.return_value = [0]
    ch = SamsungFlashChannel(ocd, 0)
    with patch("time.time", side_effect=[0, 0, 10]):
        ch.read_sa_page(0x10, 0x02, mem_addr=0x84938000)
    ocd.halt.assert_called()
    assert ocd.cmd.called


def test_flash_channel_write_sa_ruw():
    ocd = _mock_ocd()
    ocd.read_memory.return_value = [0]
    ch = SamsungFlashChannel(ocd, 0)
    with patch("time.time", side_effect=[0, 0, 10]):
        ch.write_sa_ruw(0x10, 0x02, mem_addr=0x84938000)
    ocd.halt.assert_called()
    assert ocd.cmd.called


def test_flash_channel_pbpn_encoding():
    ocd = _mock_ocd()
    ocd.read_memory.return_value = [0]
    ch = SamsungFlashChannel(ocd, 0)
    with patch("time.time", side_effect=[0, 0, 10]):
        ch.read_page(0xAB, 0xCD)
    expected_pbpn = (0xAB << 8) | 0xCD
    from unittest.mock import call
    ocd.cmd.assert_any_call(
        f"mww 0x{ch._fch(SamsungMEXMap.FCH_PBPN):08X} 0x{expected_pbpn:08X}"
    )

