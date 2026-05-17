import struct

from hdd_toolkit.ata.seagate_vsc import (
    SCT_CYL_HI,
    SCT_CYL_LO,
    SCT_LOG_CMD,
    SCT_LOG_DATA,
    SMART_READ_LOG,
    SMART_WRITE_LOG,
    SeagateF3SCTClient,
    SeagateSAModule,
    _SCT_SA_ACTION,
    _SCT_SA_READ,
    _SCT_SA_WRITE,
)


# ---------------------------------------------------------------------------
# SeagateSAModule enum
# ---------------------------------------------------------------------------


def test_seagate_sa_module_values():
    assert SeagateSAModule.ROM_RESIDENT_0 == 0x03
    assert SeagateSAModule.ROM_RESIDENT_1 == 0x0B
    assert SeagateSAModule.PHYSICAL_OVERLAY_0 == 0x1D
    assert SeagateSAModule.PHYSICAL_OVERLAY_1 == 0x1E
    assert SeagateSAModule.PHYSICAL_OVERLAY_2 == 0x1F
    assert SeagateSAModule.CONGEN_XML == 0x34


def test_seagate_sa_module_count():
    assert len(SeagateSAModule) == 6


# ---------------------------------------------------------------------------
# SCT log address constants
# ---------------------------------------------------------------------------


def test_sct_log_addresses():
    assert SCT_LOG_CMD == 0xE0
    assert SCT_LOG_DATA == 0xE1
    assert SCT_CYL_LO == 0x4F
    assert SCT_CYL_HI == 0xC2
    assert SMART_WRITE_LOG == 0xD6
    assert SMART_READ_LOG == 0xD5


# ---------------------------------------------------------------------------
# SeagateF3SCTClient._build_sa_cmd
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


def test_build_sa_cmd_read():
    dev = _MockDevice()
    client = SeagateF3SCTClient(dev)
    buf = client._build_sa_cmd(_SCT_SA_READ, 0x1D)
    assert buf[0] == _SCT_SA_ACTION
    assert buf[1] == _SCT_SA_READ
    mod_id = struct.unpack_from("<H", buf, 2)[0]
    assert mod_id == 0x1D
    assert len(buf) == 512


def test_build_sa_cmd_write():
    dev = _MockDevice()
    client = SeagateF3SCTClient(dev)
    buf = client._build_sa_cmd(_SCT_SA_WRITE, 0x34)
    assert buf[0] == _SCT_SA_ACTION
    assert buf[1] == _SCT_SA_WRITE
    mod_id = struct.unpack_from("<H", buf, 2)[0]
    assert mod_id == 0x34


# ---------------------------------------------------------------------------
# SeagateF3SCTClient._sct_write_cmd uses SCT_LOG_CMD
# ---------------------------------------------------------------------------


def test_sct_write_cmd_uses_log_cmd():
    dev = _MockDevice()
    client = SeagateF3SCTClient(dev)
    buf = b"\xD0\x01\x1D\x00" + b"\x00" * 508
    client._sct_write_cmd(buf)
    assert len(dev.calls) == 1
    regs = dev.calls[0]["regs"]
    assert regs["lba_lo"] == SCT_LOG_CMD
    assert regs["features"] == SMART_WRITE_LOG
    assert dev.calls[0]["data_out"] == buf


# ---------------------------------------------------------------------------
# SeagateF3SCTClient._sct_read_data uses SCT_LOG_DATA
# ---------------------------------------------------------------------------


def test_sct_read_data_uses_log_data():
    dev = _MockDevice(return_data=b"\xAA" * 512)
    client = SeagateF3SCTClient(dev)
    result = client._sct_read_data(1)
    assert len(dev.calls) == 1
    regs = dev.calls[0]["regs"]
    assert regs["lba_lo"] == SCT_LOG_DATA
    assert regs["features"] == SMART_READ_LOG
    assert result == b"\xAA" * 512


# ---------------------------------------------------------------------------
# SeagateF3SCTClient.read_module stops on all-0xFF chunk
# ---------------------------------------------------------------------------


def test_read_module_stops_on_ff():
    dev = _MockDevice(return_data=b"\xFF" * 4096)
    client = SeagateF3SCTClient(dev)
    data = client.read_module(0x1D)
    assert data == b""


def test_read_module_returns_data():
    payload = b"\xAB\xCD\xEF" * 100 + b"\x00" * (4096 - 300)
    dev = _MockDevice(return_data=payload)
    client = SeagateF3SCTClient(dev)
    data = client.read_module(0x1D)
    assert len(data) > 0
    assert data[:3] == b"\xAB\xCD\xEF"


# ---------------------------------------------------------------------------
# SeagateF3SCTClient.list_modules skips ATAError and empty modules
# ---------------------------------------------------------------------------


def test_list_modules_empty_drive():
    dev = _MockDevice(return_data=b"\xFF" * 4096)
    client = SeagateF3SCTClient(dev)
    modules = client.list_modules(max_module=4)
    assert modules == {}
