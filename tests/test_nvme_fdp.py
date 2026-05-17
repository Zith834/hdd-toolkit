import struct

import pytest

from hdd_toolkit.nvme.admin import NVMeAdminCmd, NVMeAdminPassthrough
from hdd_toolkit.nvme.fdp import (
    FDPPlacementHint,
    RUHAssigner,
    build_fdp_events_cmd,
    build_fdp_status_cmd,
    build_fdp_write_cmd,
    parse_fdp_status,
)


class TestFDPPlacementHint:
    def test_dtype_default(self):
        hint = FDPPlacementHint(nsid=1, ruh_id=3)
        assert hint.dtype == 2

    def test_dspec_equals_ruh_id(self):
        hint = FDPPlacementHint(nsid=1, ruh_id=5)
        assert hint.dspec == 5

    def test_dspec_masked_to_16bit(self):
        hint = FDPPlacementHint(nsid=1, ruh_id=0x1FFFF)
        assert hint.dspec == 0xFFFF


class TestBuildFDPWriteCmd:
    def test_opcode(self):
        cmd = build_fdp_write_cmd(nsid=1, slba=0, nlb=0, ruh_id=0)
        assert cmd.opcode == 0x01

    def test_dtype_in_cdw12(self):
        cmd = build_fdp_write_cmd(nsid=1, slba=0, nlb=7, ruh_id=0)
        dtype = (cmd.cdw12 >> 20) & 0x07
        assert dtype == 2

    def test_ruh_id_in_cdw13(self):
        cmd = build_fdp_write_cmd(nsid=1, slba=0, nlb=0, ruh_id=4)
        assert (cmd.cdw13 & 0xFFFF) == 4

    def test_slba_encoded(self):
        cmd = build_fdp_write_cmd(nsid=1, slba=0x1_0000_0000, nlb=0, ruh_id=0)
        assert cmd.cdw10 == 0
        assert cmd.cdw11 == 1

    def test_is_write(self):
        cmd = build_fdp_write_cmd(nsid=1, slba=0, nlb=0, ruh_id=0)
        assert cmd.is_write is True

    def test_data_attached(self):
        payload = b"\xAA" * 512
        cmd = build_fdp_write_cmd(nsid=1, slba=0, nlb=0, ruh_id=0, data=payload)
        assert cmd.data == payload
        assert cmd.data_len == 512


class TestBuildFDPStatusCmd:
    def test_opcode(self):
        cmd = build_fdp_status_cmd()
        assert cmd.opcode == NVMeAdminPassthrough.GET_LOG_PAGE

    def test_log_id(self):
        cmd = build_fdp_status_cmd()
        assert (cmd.cdw10 & 0xFF) == 0x70

    def test_data_len(self):
        cmd = build_fdp_status_cmd()
        assert cmd.data_len == 512


class TestBuildFDPEventsCmd:
    def test_log_id(self):
        cmd = build_fdp_events_cmd()
        assert (cmd.cdw10 & 0xFF) == 0x71

    def test_type(self):
        assert isinstance(build_fdp_events_cmd(), NVMeAdminCmd)


class TestParseFDPStatus:
    def _make_log(self, num_ruhs: int = 2) -> bytes:
        buf = bytearray(512)
        struct.pack_into("<H", buf, 0, num_ruhs)
        struct.pack_into("<H", buf, 2, 8)
        for i in range(num_ruhs):
            off = 8 + i * 8
            struct.pack_into("<HBB", buf, off, i, i % 3, i)
            struct.pack_into("<I", buf, off + 4, 1024 * (i + 1))
        return bytes(buf)

    def test_num_ruhs(self):
        result = parse_fdp_status(self._make_log(3))
        assert result["num_ruhs"] == 3

    def test_descriptor_count(self):
        result = parse_fdp_status(self._make_log(2))
        assert len(result["descriptors"]) == 2

    def test_descriptor_fields(self):
        result = parse_fdp_status(self._make_log(2))
        desc = result["descriptors"][0]
        assert "ruh_id" in desc
        assert "ruh_type" in desc
        assert "placement_id" in desc
        assert "ruamw" in desc

    def test_ruamw_value(self):
        result = parse_fdp_status(self._make_log(1))
        assert result["descriptors"][0]["ruamw"] == 1024

    def test_short_data(self):
        result = parse_fdp_status(b"\x00" * 4)
        assert "error" in result

    def test_empty_log(self):
        result = parse_fdp_status(self._make_log(0))
        assert result["num_ruhs"] == 0
        assert result["descriptors"] == []


class TestRUHAssigner:
    def test_first_assign_returns_cold_ruh(self):
        assigner = RUHAssigner(hot_ruh_id=0, cold_ruh_id=1)
        ruh = assigner.assign(lba=100, size_bytes=4096, timestamp=0.0)
        assert ruh == 1

    def test_hot_overwrite_returns_hot_ruh(self):
        assigner = RUHAssigner(
            hot_ruh_id=0, cold_ruh_id=1, deathtime_threshold_ms=5000.0
        )
        assigner.assign(lba=100, size_bytes=4096, timestamp=0.0)
        ruh = assigner.assign(lba=100, size_bytes=4096, timestamp=1.0)
        assert ruh == 0

    def test_cold_overwrite_returns_cold_ruh(self):
        assigner = RUHAssigner(
            hot_ruh_id=0, cold_ruh_id=1, deathtime_threshold_ms=500.0
        )
        assigner.assign(lba=200, size_bytes=4096, timestamp=0.0)
        ruh = assigner.assign(lba=200, size_bytes=4096, timestamp=10.0)
        assert ruh == 1

    def test_assignment_log_grows(self):
        assigner = RUHAssigner()
        assigner.assign(lba=0, size_bytes=512, timestamp=0.0)
        assigner.assign(lba=0, size_bytes=512, timestamp=1.0)
        log = assigner.assignment_log()
        assert len(log) == 2

    def test_build_write_cmd_type(self):
        assigner = RUHAssigner()
        cmd = assigner.build_write_cmd(nsid=1, lba=0, nlb=0, size_bytes=512, timestamp=0.0)
        assert isinstance(cmd, NVMeAdminCmd)
        assert cmd.opcode == 0x01
