import struct

import pytest

from hdd_toolkit.hw.gc_inference import GCUnitInferrer, GCSweepPoint


def _make_c1_buf(nand: int = 0, host: int = 0) -> bytes:
    buf = bytearray(512)
    struct.pack_into("<QQ", buf, 0x00, nand, 0)
    struct.pack_into("<QQ", buf, 0x10, host, 0)
    return bytes(buf)


class TestBuildFillSequence:
    def test_empty_on_zero_capacity(self):
        seq = GCUnitInferrer.build_fill_sequence(0, 0.8)
        assert seq == []

    def test_empty_on_bad_ratio(self):
        assert GCUnitInferrer.build_fill_sequence(1000, 0.0) == []

    def test_covers_target_lba_range(self):
        seq = GCUnitInferrer.build_fill_sequence(1000, 0.5, block_size_lba=10)
        last_lba, last_nlb = seq[-1]
        assert last_lba + last_nlb + 1 <= 500

    def test_no_overlap(self):
        seq = GCUnitInferrer.build_fill_sequence(256, 1.0, block_size_lba=8)
        for i in range(len(seq) - 1):
            cur_end = seq[i][0] + seq[i][1] + 1
            assert cur_end == seq[i + 1][0]

    def test_starts_at_zero(self):
        seq = GCUnitInferrer.build_fill_sequence(100, 0.5)
        assert seq[0][0] == 0

    def test_sequence_not_empty(self):
        seq = GCUnitInferrer.build_fill_sequence(512, 0.8)
        assert len(seq) > 0

    def test_fill_ratio_respected(self):
        capacity = 1024
        ratio = 0.25
        seq = GCUnitInferrer.build_fill_sequence(capacity, ratio, block_size_lba=8)
        total_lba = sum(nlb + 1 for _, nlb in seq)
        assert total_lba <= int(capacity * ratio) + 8


class TestGCUnitInferrer:
    def _snap_high_waf(self, block_size: int):
        before = _make_c1_buf(nand=1000, host=500)
        after = _make_c1_buf(nand=3000, host=1000)
        return before, after

    def _snap_low_waf_at(self, aligned_size: int):
        def _snap(block_size: int):
            if block_size >= aligned_size:
                before = _make_c1_buf(nand=1000, host=1000)
                after = _make_c1_buf(nand=2005, host=2000)
            else:
                before = _make_c1_buf(nand=1000, host=500)
                after = _make_c1_buf(nand=3000, host=1000)
            return before, after
        return _snap

    def test_sweep_returns_sorted_points(self):
        inferrer = GCUnitInferrer()
        points = inferrer.sweep(self._snap_high_waf, block_sizes=[16384, 4096, 8192])
        sizes = [p.block_size for p in points]
        assert sizes == sorted(sizes)

    def test_sweep_point_type(self):
        inferrer = GCUnitInferrer()
        points = inferrer.sweep(self._snap_high_waf, block_sizes=[4096])
        assert isinstance(points[0], GCSweepPoint)

    def test_sweep_default_sizes(self):
        inferrer = GCUnitInferrer()
        points = inferrer.sweep(self._snap_high_waf)
        assert len(points) == len(GCUnitInferrer.DEFAULT_BLOCK_SIZES)

    def test_estimate_gc_unit_found(self):
        inferrer = GCUnitInferrer()
        snap = self._snap_low_waf_at(65536)
        points = inferrer.sweep(snap, block_sizes=[4096, 32768, 65536, 131072])
        gc_unit = GCUnitInferrer.estimate_gc_unit(points)
        assert gc_unit == 65536

    def test_estimate_gc_unit_not_found(self):
        inferrer = GCUnitInferrer()
        points = inferrer.sweep(self._snap_high_waf, block_sizes=[4096, 8192])
        assert GCUnitInferrer.estimate_gc_unit(points) == 0

    def test_estimate_gc_unit_empty(self):
        assert GCUnitInferrer.estimate_gc_unit([]) == 0

    def test_sweep_waf_non_negative(self):
        inferrer = GCUnitInferrer()
        points = inferrer.sweep(self._snap_high_waf, block_sizes=[4096, 65536])
        for p in points:
            assert p.waf >= 0.0

    def test_waf_aligned_threshold(self):
        assert GCUnitInferrer.WAF_ALIGNED_THRESHOLD == pytest.approx(1.1)
