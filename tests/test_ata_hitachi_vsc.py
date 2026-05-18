import struct

import pytest

from hdd_toolkit.ata.hitachi_vsc import (
    HITACHI_FEAT_DIAG_MODE,
    HITACHI_FEAT_FW_MODE,
    HITACHI_FEAT_SA_READ,
    HITACHI_FEAT_SA_WRITE,
    HITACHI_SA_CMD_LOG,
    HITACHI_SA_DATA_LOG,
    HitachiSAModule,
    HitachiVSCClient,
)


# ---------------------------------------------------------------------------
# HitachiSAModule enum
# ---------------------------------------------------------------------------


def test_sa_module_boot_code():
    assert HitachiSAModule.BOOT_CODE == 0x00


def test_sa_module_translator():
    assert HitachiSAModule.TRANSLATOR == 0x01


def test_sa_module_p_list():
    assert HitachiSAModule.P_LIST == 0x02


def test_sa_module_g_list():
    assert HitachiSAModule.G_LIST == 0x03


def test_sa_module_smart_log():
    assert HitachiSAModule.SMART_LOG == 0x04


def test_sa_module_adaptive_writes():
    assert HitachiSAModule.ADAPTIVE_WRITES == 0x08


def test_sa_module_zone_bit():
    assert HitachiSAModule.ZONE_BIT == 0x0A


def test_sa_module_count():
    assert len(HitachiSAModule) == 9


# ---------------------------------------------------------------------------
# Log address and feature constants
# ---------------------------------------------------------------------------


def test_sa_cmd_log_address():
    assert HITACHI_SA_CMD_LOG == 0x02


def test_sa_data_log_address():
    assert HITACHI_SA_DATA_LOG == 0x03


def test_feat_sa_read():
    assert HITACHI_FEAT_SA_READ == 0x45


def test_feat_sa_write():
    assert HITACHI_FEAT_SA_WRITE == 0x46


def test_feat_diag_mode():
    assert HITACHI_FEAT_DIAG_MODE == 0xD0


def test_feat_fw_mode():
    assert HITACHI_FEAT_FW_MODE == 0xF8


# ---------------------------------------------------------------------------
# HitachiVSCClient._build_sa_cmd_buf
# ---------------------------------------------------------------------------


class _MockDevice:
    def __init__(self, return_data: bytes = b""):
        self.calls = []
        self._return_data = return_data

    def passthrough(self, regs, data_out=None, data_in_size=0):
        self.calls.append({"regs": regs, "data_out": data_out, "data_in_size": data_in_size})
        if data_in_size:
            return self._return_data[:data_in_size].ljust(data_in_size, b"\xFF")
        return b""


def test_build_sa_cmd_buf_read_op():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    buf = client._build_sa_cmd_buf(0x01, HitachiSAModule.TRANSLATOR)
    assert buf[0] == 0x01
    assert buf[1] == HitachiSAModule.TRANSLATOR
    assert len(buf) == 512


def test_build_sa_cmd_buf_write_op():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    buf = client._build_sa_cmd_buf(0x02, HitachiSAModule.G_LIST, length_sectors=4)
    assert buf[0] == 0x02
    assert buf[1] == HitachiSAModule.G_LIST
    length = struct.unpack_from("<H", buf, 2)[0]
    assert length == 4


def test_build_sa_cmd_buf_length_zero_default():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    buf = client._build_sa_cmd_buf(0x01, 0x00)
    length = struct.unpack_from("<H", buf, 2)[0]
    assert length == 0


# ---------------------------------------------------------------------------
# HitachiVSCClient._write_cmd_log uses HITACHI_FEAT_SA_WRITE + SA_CMD_LOG
# ---------------------------------------------------------------------------


def test_write_cmd_log_uses_correct_log_address():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    buf = b"\x01" + b"\x00" * 511
    client._write_cmd_log(buf)
    assert len(dev.calls) == 1
    regs = dev.calls[0]["regs"]
    assert regs["lba_lo"] == HITACHI_SA_CMD_LOG
    assert regs["features"] == HITACHI_FEAT_SA_WRITE


def test_write_cmd_log_sends_buffer():
    payload = b"\xDE\xAD" + b"\x00" * 510
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    client._write_cmd_log(payload)
    assert dev.calls[0]["data_out"] == payload


# ---------------------------------------------------------------------------
# HitachiVSCClient._read_data_log uses HITACHI_FEAT_SA_READ + SA_DATA_LOG
# ---------------------------------------------------------------------------


def test_read_data_log_uses_correct_log_address():
    dev = _MockDevice(return_data=b"\xAB" * 512)
    client = HitachiVSCClient(dev)
    client._read_data_log(1)
    assert len(dev.calls) == 1
    regs = dev.calls[0]["regs"]
    assert regs["lba_lo"] == HITACHI_SA_DATA_LOG
    assert regs["features"] == HITACHI_FEAT_SA_READ


def test_read_data_log_returns_data():
    dev = _MockDevice(return_data=b"\xAB" * 512)
    client = HitachiVSCClient(dev)
    result = client._read_data_log(1)
    assert result == b"\xAB" * 512


# ---------------------------------------------------------------------------
# HitachiVSCClient.read_module
# ---------------------------------------------------------------------------


def test_read_module_stops_on_all_ff():
    dev = _MockDevice(return_data=b"\xFF" * 512)
    client = HitachiVSCClient(dev)
    data = client.read_module(HitachiSAModule.BOOT_CODE)
    assert data == b""


def test_read_module_returns_non_ff_data():
    payload = b"\xAB\xCD\xEF" * 100 + b"\x00" * (512 - 300)
    dev = _MockDevice(return_data=payload)
    client = HitachiVSCClient(dev)
    data = client.read_module(HitachiSAModule.TRANSLATOR)
    assert len(data) > 0
    assert data[:3] == b"\xAB\xCD\xEF"


def test_read_module_issues_cmd_then_data():
    dev = _MockDevice(return_data=b"\xFF" * 512)
    client = HitachiVSCClient(dev)
    client.read_module(0x02)
    write_calls = [c for c in dev.calls if c["data_out"] is not None]
    assert len(write_calls) >= 1
    assert write_calls[0]["regs"]["lba_lo"] == HITACHI_SA_CMD_LOG


# ---------------------------------------------------------------------------
# HitachiVSCClient.write_module
# ---------------------------------------------------------------------------


def test_write_module_sends_cmd_first():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    client.write_module(HitachiSAModule.G_LIST, b"\x00" * 512)
    write_calls = [c for c in dev.calls if c["data_out"] is not None]
    assert write_calls[0]["regs"]["lba_lo"] == HITACHI_SA_CMD_LOG


def test_write_module_sends_data():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    payload = b"\xBE\xEF" * 256
    client.write_module(HitachiSAModule.P_LIST, payload)
    data_calls = [c for c in dev.calls if c["regs"]["lba_lo"] == HITACHI_SA_DATA_LOG]
    assert len(data_calls) >= 1


# ---------------------------------------------------------------------------
# HitachiVSCClient.list_modules
# ---------------------------------------------------------------------------


def test_list_modules_empty_on_all_ff():
    dev = _MockDevice(return_data=b"\xFF" * 512)
    client = HitachiVSCClient(dev)
    result = client.list_modules(max_module=4)
    assert result == {}


def test_list_modules_returns_non_ff_modules():
    dev = _MockDevice(return_data=b"\xAB" * 512)
    client = HitachiVSCClient(dev)
    result = client.list_modules(max_module=3)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# HitachiVSCClient.probe_capabilities
# ---------------------------------------------------------------------------


def test_probe_capabilities_returns_dict():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    caps = client.probe_capabilities()
    assert isinstance(caps, dict)
    assert "vendor" in caps
    assert "Hitachi" in caps["vendor"]


def test_probe_capabilities_known_modules():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    caps = client.probe_capabilities()
    assert 0x00 in caps["known_modules"]
    assert 0x03 in caps["known_modules"]


def test_probe_capabilities_feat_values():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    caps = client.probe_capabilities()
    assert caps["feat_sa_read"] == hex(HITACHI_FEAT_SA_READ)
    assert caps["feat_sa_write"] == hex(HITACHI_FEAT_SA_WRITE)


def test_probe_capabilities_does_not_send_commands():
    dev = _MockDevice()
    client = HitachiVSCClient(dev)
    client.probe_capabilities()
    assert dev.calls == []
