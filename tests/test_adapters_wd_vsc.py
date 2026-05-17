import pytest

from hdd_toolkit.ata.wd_vsc import WD_DATA_LOG_ADDR, WD_SA_ROM_MAP, WDVSCClient


class _MockDevice:
    def __init__(self, return_data: bytes = b""):
        self.calls = []
        self._return_data = return_data

    def passthrough(self, regs, data_out=None, data_in_size=0):
        self.calls.append({"regs": regs, "data_out": data_out, "data_in_size": data_in_size})
        if data_in_size:
            return self._return_data[:data_in_size].ljust(data_in_size, b"\xFF")
        return b""


def test_wd_data_log_addr():
    assert WD_DATA_LOG_ADDR == 0xBF


def test_wd_sa_rom_map_keys():
    expected = {0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x109}
    assert set(WD_SA_ROM_MAP.keys()) == expected


def test_wd_sa_rom_map_values():
    assert WD_SA_ROM_MAP[0x102] == 0x0A
    assert WD_SA_ROM_MAP[0x103] == 0x47
    assert WD_SA_ROM_MAP[0x104] == 0x0D
    assert WD_SA_ROM_MAP[0x105] == 0x30
    assert WD_SA_ROM_MAP[0x106] == 0x4F
    assert WD_SA_ROM_MAP[0x107] == 0x0B
    assert WD_SA_ROM_MAP[0x109] is None


def test_wd_enable_firmware_mode_no_dev():
    with pytest.raises(AttributeError):
        WDVSCClient(None).enable_firmware_mode()


def test_wd_smart_read_uses_data_log():
    dev = _MockDevice(return_data=b"\x00" * 512)
    client = WDVSCClient(dev)
    client._smart_read(512)
    read_calls = [c for c in dev.calls if c["regs"].get("features") == 0xD5]
    assert len(read_calls) == 1
    assert read_calls[0]["regs"]["lba_lo"] == WD_DATA_LOG_ADDR
