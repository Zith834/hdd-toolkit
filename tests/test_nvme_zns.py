import struct

import pytest

from hdd_toolkit.nvme.admin import NVMeAdminCmd
from hdd_toolkit.nvme.zns import (
    ZNSZoneDescriptor,
    ZNSSweeper,
    ZoneAction,
    ZoneReportAction,
    build_zone_append,
    build_zone_mgmt_recv,
    build_zone_mgmt_send,
    parse_zone_report,
)


class TestZoneAction:
    def test_constants(self):
        assert ZoneAction.CLOSE == 0x01
        assert ZoneAction.FINISH == 0x02
        assert ZoneAction.OPEN == 0x03
        assert ZoneAction.RESET == 0x04
        assert ZoneAction.OFFLINE == 0x05


class TestBuildZoneMgmtSend:
    def test_opcode(self):
        cmd = build_zone_mgmt_send(nsid=1, slba=0, action=ZoneAction.RESET)
        assert cmd.opcode == 0x79

    def test_action_in_cdw13(self):
        cmd = build_zone_mgmt_send(nsid=1, slba=0, action=ZoneAction.OPEN)
        assert (cmd.cdw13 & 0x0F) == ZoneAction.OPEN

    def test_slba_split(self):
        slba = 0x2_0000_0000
        cmd = build_zone_mgmt_send(nsid=1, slba=slba, action=ZoneAction.RESET)
        assert cmd.cdw10 == 0
        assert cmd.cdw11 == 2

    def test_select_all_flag(self):
        cmd = build_zone_mgmt_send(nsid=1, slba=0, action=ZoneAction.RESET, select_all=True)
        assert (cmd.cdw13 >> 8) & 1 == 1

    def test_select_all_false(self):
        cmd = build_zone_mgmt_send(nsid=1, slba=0, action=ZoneAction.RESET, select_all=False)
        assert (cmd.cdw13 >> 8) & 1 == 0

    def test_nsid(self):
        cmd = build_zone_mgmt_send(nsid=5, slba=0, action=ZoneAction.CLOSE)
        assert cmd.nsid == 5


class TestBuildZoneMgmtRecv:
    def test_opcode(self):
        cmd = build_zone_mgmt_recv(nsid=1, slba=0)
        assert cmd.opcode == 0x7A

    def test_action_in_cdw13(self):
        cmd = build_zone_mgmt_recv(nsid=1, slba=0, action=ZoneReportAction.FULL)
        assert (cmd.cdw13 & 0xFF) == ZoneReportAction.FULL

    def test_data_len(self):
        cmd = build_zone_mgmt_recv(nsid=1, slba=0, data_len=4096)
        assert cmd.data_len == 4096

    def test_slba_high(self):
        slba = 0x1_0000_0000
        cmd = build_zone_mgmt_recv(nsid=1, slba=slba)
        assert cmd.cdw11 == 1


class TestBuildZoneAppend:
    def test_opcode(self):
        cmd = build_zone_append(nsid=1, zone_slba=0, nlb=7)
        assert cmd.opcode == 0x7D

    def test_is_write(self):
        cmd = build_zone_append(nsid=1, zone_slba=0, nlb=0)
        assert cmd.is_write is True

    def test_nlb_in_cdw12(self):
        cmd = build_zone_append(nsid=1, zone_slba=0, nlb=15)
        assert (cmd.cdw12 & 0xFFFF) == 15

    def test_data_len(self):
        payload = b"\x55" * 4096
        cmd = build_zone_append(nsid=1, zone_slba=0, nlb=0, data=payload)
        assert cmd.data_len == 4096

    def test_zone_slba_split(self):
        slba = 0x3_0000_0000
        cmd = build_zone_append(nsid=1, zone_slba=slba, nlb=0)
        assert cmd.cdw10 == 0
        assert cmd.cdw11 == 3


class TestParseZoneReport:
    def _make_report(self, zones: list[dict]) -> bytes:
        buf = bytearray(16 + 64 * len(zones))
        struct.pack_into("<Q", buf, 0, len(zones))
        for i, z in enumerate(zones):
            off = 16 + i * 64
            buf[off] = z.get("zone_type", 2) & 0x0F
            buf[off + 1] = (z.get("zone_state", 1) & 0x0F) << 4
            struct.pack_into("<Q", buf, off + 8, z.get("zone_capacity", 2048))
            struct.pack_into("<Q", buf, off + 16, z.get("zone_start_lba", i * 2048))
            struct.pack_into("<Q", buf, off + 24, z.get("write_pointer", i * 2048))
        return bytes(buf)

    def test_empty_report(self):
        buf = bytearray(16)
        struct.pack_into("<Q", buf, 0, 0)
        result = parse_zone_report(bytes(buf))
        assert result == []

    def test_short_data(self):
        result = parse_zone_report(b"\x00" * 8)
        assert result == []

    def test_single_zone(self):
        buf = self._make_report([{"zone_start_lba": 0, "zone_capacity": 2048, "zone_state": 1}])
        result = parse_zone_report(buf)
        assert len(result) == 1
        assert isinstance(result[0], ZNSZoneDescriptor)

    def test_zone_fields(self):
        buf = self._make_report([{
            "zone_start_lba": 0x1000,
            "zone_capacity": 512,
            "write_pointer": 0x1010,
            "zone_state": 0x04,
        }])
        z = parse_zone_report(buf)[0]
        assert z.zone_start_lba == 0x1000
        assert z.zone_capacity == 512
        assert z.write_pointer == 0x1010
        assert z.zone_state == 0x04

    def test_multiple_zones(self):
        zones = [{"zone_start_lba": i * 2048} for i in range(4)]
        result = parse_zone_report(self._make_report(zones))
        assert len(result) == 4

    def test_is_empty_flag(self):
        buf = self._make_report([{"zone_state": 0x01}])
        z = parse_zone_report(buf)[0]
        assert z.is_empty is True
        assert z.is_full is False

    def test_is_full_flag(self):
        buf = self._make_report([{"zone_state": 0x0E}])
        z = parse_zone_report(buf)[0]
        assert z.is_full is True


class TestZNSSweeper:
    def _make_c1_buf(self, nand: int, host: int) -> bytes:
        buf = bytearray(512)
        struct.pack_into("<QQ", buf, 0x00, nand, 0)
        struct.pack_into("<QQ", buf, 0x10, host, 0)
        return bytes(buf)

    def _snap_func_high_waf(self, write_size: int):
        before = self._make_c1_buf(1000, 500)
        after = self._make_c1_buf(3000, 1000)
        return before, after

    def _snap_func_low_waf(self, write_size: int):
        before = self._make_c1_buf(1000, 1000)
        after = self._make_c1_buf(2010, 2000)
        return before, after

    def test_sweep_result_count(self):
        sweeper = ZNSSweeper(nsid=1)
        results = sweeper.sweep(self._snap_func_high_waf, write_sizes=[4096, 8192, 16384])
        assert len(results) == 3

    def test_sweep_sorted_by_write_size(self):
        sweeper = ZNSSweeper(nsid=1)
        results = sweeper.sweep(self._snap_func_high_waf, write_sizes=[16384, 4096])
        assert results[0]["write_size"] < results[1]["write_size"]

    def test_sweep_keys(self):
        sweeper = ZNSSweeper(nsid=1)
        results = sweeper.sweep(self._snap_func_high_waf, write_sizes=[4096])
        assert "write_size" in results[0]
        assert "waf" in results[0]
        assert "nand_delta" in results[0]
        assert "host_delta" in results[0]

    def test_estimate_gc_unit_found(self):
        sweeper = ZNSSweeper(nsid=1)
        results = sweeper.sweep(self._snap_func_low_waf, write_sizes=[4096, 65536])
        gc_unit = sweeper.estimate_gc_unit(results)
        assert gc_unit in {4096, 65536}

    def test_estimate_gc_unit_not_found(self):
        sweeper = ZNSSweeper(nsid=1)
        results = sweeper.sweep(self._snap_func_high_waf, write_sizes=[4096])
        assert sweeper.estimate_gc_unit(results) == 0

    def test_default_write_sizes(self):
        sweeper = ZNSSweeper(nsid=1)
        results = sweeper.sweep(self._snap_func_high_waf)
        assert len(results) == 6
