import struct

from hdd_firmware_toolkit.hw.hpa_dco import HPADCOAccess


def test_detect_hpa_from_identify():
    identify = bytearray(512)
    identify[60:62] = struct.pack("<H", 10000)
    identify[100:104] = struct.pack("<I", 20000)
    result = HPADCOAccess.detect_hpa_from_identify(bytes(identify))
    assert "hpa_active" in result
    assert "total_lba_28" in result


def test_detect_hpa_from_identify_short():
    result = HPADCOAccess.detect_hpa_from_identify(b"")
    assert result["hpa_active"] is False


def test_build_read_native_max_cmd_48():
    cmd = HPADCOAccess.build_read_native_max_cmd(lba48=True)
    assert cmd is not None


def test_build_set_max_cmd():
    cmd = HPADCOAccess.build_set_max_cmd(lba=100000, persistent=True)
    assert cmd is not None


def test_build_dco_identify_cmd():
    cmd = HPADCOAccess.build_dco_identify_cmd()
    assert cmd is not None


def test_build_dco_set_cmd():
    cmd = HPADCOAccess.build_dco_set_cmd(dco_data=b"\x00" * 512)
    assert cmd is not None


def test_build_dco_restore_cmd():
    cmd = HPADCOAccess.build_dco_restore_cmd()
    assert cmd is not None


def test_parse_dco_data():
    data = bytearray(512)
    data[3] = 0x01
    data[5] = 0x02
    data[8:12] = struct.pack("<I", 1000)
    result = HPADCOAccess.parse_dco_data(bytes(data))
    assert "features" in result
