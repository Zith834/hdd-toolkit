import struct

import pytest

from hdd_toolkit.nvme.admin import NVMeAdminCmd, NVMeAdminPassthrough
from hdd_toolkit.nvme.waf import WAFMeter, WAFProfile, WAFSweepPoint, WorkloadClassifier, waf_sweep


def _make_c1_buf(nand_lo: int = 0, nand_hi: int = 0, host_lo: int = 0, host_hi: int = 0) -> bytes:
    """Build a minimal 512-byte OCP C1 log buffer."""
    buf = bytearray(512)
    struct.pack_into("<QQ", buf, 0x00, nand_lo, nand_hi)
    struct.pack_into("<QQ", buf, 0x10, host_lo, host_hi)
    return bytes(buf)


class TestWAFMeter:
    def test_build_ocp_waf_log_cmd_type(self):
        cmd = WAFMeter.build_ocp_waf_log_cmd()
        assert isinstance(cmd, NVMeAdminCmd)
        assert cmd.opcode == NVMeAdminPassthrough.GET_LOG_PAGE
        assert cmd.data_len == WAFMeter.OCP_LOG_C1_SIZE

    def test_build_ocp_waf_log_cmd_log_id(self):
        cmd = WAFMeter.build_ocp_waf_log_cmd()
        assert (cmd.cdw10 & 0xFF) == WAFMeter.OCP_LOG_C1

    def test_parse_ocp_waf_fields_basic(self):
        buf = _make_c1_buf(nand_lo=2000, host_lo=1000)
        result = WAFMeter.parse_ocp_waf_fields(buf)
        assert result["nand_written"] == 2000
        assert result["host_written"] == 1000
        assert result["waf"] == pytest.approx(2.0)

    def test_parse_ocp_waf_fields_128bit(self):
        nand = (1 << 64) + 500
        host = (1 << 64) + 500
        buf = _make_c1_buf(
            nand_lo=nand & 0xFFFFFFFFFFFFFFFF,
            nand_hi=(nand >> 64) & 0xFFFFFFFFFFFFFFFF,
            host_lo=host & 0xFFFFFFFFFFFFFFFF,
            host_hi=(host >> 64) & 0xFFFFFFFFFFFFFFFF,
        )
        result = WAFMeter.parse_ocp_waf_fields(buf)
        assert result["waf"] == pytest.approx(1.0)

    def test_parse_ocp_waf_fields_short(self):
        result = WAFMeter.parse_ocp_waf_fields(b"\x00" * 16)
        assert "error" in result

    def test_parse_ocp_waf_fields_zero_host(self):
        buf = _make_c1_buf(nand_lo=100, host_lo=0)
        result = WAFMeter.parse_ocp_waf_fields(buf)
        assert result["waf"] == 0.0

    def test_compute_waf(self):
        assert WAFMeter.compute_waf(300, 100) == pytest.approx(3.0)

    def test_compute_waf_zero_host(self):
        assert WAFMeter.compute_waf(100, 0) == 0.0

    def test_delta_waf(self):
        meter = WAFMeter()
        meter.snapshot_before(_make_c1_buf(nand_lo=1000, host_lo=500))
        meter.snapshot_after(_make_c1_buf(nand_lo=3000, host_lo=1500))
        delta = meter.delta_waf()
        assert delta["delta_nand_written"] == 2000
        assert delta["delta_host_written"] == 1000
        assert delta["waf"] == pytest.approx(2.0)

    def test_delta_waf_error_on_bad_before(self):
        meter = WAFMeter()
        meter._snap_before = {"error": "bad"}
        meter._snap_after = {}
        delta = meter.delta_waf()
        assert "error" in delta


class TestWorkloadClassifier:
    def test_classify_sequential(self):
        stats = {"mean_us": 50.0, "p99_us": 55.0}
        profile = WorkloadClassifier.classify(stats, waf=1.01, block_size=131072)
        assert profile.pattern == "sequential"
        assert isinstance(profile, WAFProfile)

    def test_classify_random_4k(self):
        stats = {"mean_us": 50.0, "p99_us": 55.0}
        profile = WorkloadClassifier.classify(stats, waf=4.0, block_size=4096)
        assert profile.pattern == "random_4k"

    def test_classify_mixed_via_gc(self):
        stats = {"mean_us": 50.0, "p99_us": 500.0}
        profile = WorkloadClassifier.classify(stats, waf=1.5, block_size=32768)
        assert profile.pattern == "mixed"

    def test_classify_mixed_fallthrough(self):
        stats = {"mean_us": 50.0, "p99_us": 60.0}
        profile = WorkloadClassifier.classify(stats, waf=2.0, block_size=32768)
        assert profile.pattern == "mixed"

    def test_classify_from_times(self):
        times = [100.0] * 20
        profile = WorkloadClassifier.classify_from_times(times, waf=1.0, block_size=131072)
        assert isinstance(profile, WAFProfile)
        assert profile.waf == pytest.approx(1.0)

    def test_classify_empty_stats(self):
        profile = WorkloadClassifier.classify({}, waf=1.0, block_size=4096)
        assert profile.pattern in {"sequential", "random_4k", "mixed"}


class TestWAFSweep:
    def _snap_func(self, block_size: int):
        before = _make_c1_buf(nand_lo=1000, host_lo=500)
        factor = max(1, 131072 // block_size)
        after = _make_c1_buf(nand_lo=1000 + 100 * factor, host_lo=500 + 100)
        return before, after

    def test_waf_sweep_returns_all_sizes(self):
        sizes = [4096, 8192, 65536]
        results = waf_sweep(self._snap_func, block_sizes=sizes)
        assert len(results) == 3
        result_sizes = [r.block_size for r in results]
        assert result_sizes == sorted(sizes)

    def test_waf_sweep_type(self):
        results = waf_sweep(self._snap_func, block_sizes=[4096])
        assert isinstance(results[0], WAFSweepPoint)

    def test_waf_sweep_default_sizes(self):
        results = waf_sweep(self._snap_func)
        assert len(results) == 6

    def test_waf_sweep_waf_positive(self):
        results = waf_sweep(self._snap_func, block_sizes=[4096, 65536])
        for r in results:
            assert r.waf >= 0.0

    def test_waf_sweep_decreasing_waf_with_larger_blocks(self):
        results = waf_sweep(self._snap_func, block_sizes=[4096, 65536])
        waf_4k = next(r.waf for r in results if r.block_size == 4096)
        waf_64k = next(r.waf for r in results if r.block_size == 65536)
        assert waf_4k >= waf_64k
