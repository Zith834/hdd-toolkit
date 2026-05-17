import pytest

from hdd_toolkit.core.models import (
    SeparationScore,
    WAFSample,
    WriteClass,
    WriteDeathtimeClassifier,
    WriteRecord,
)


class TestWriteClass:
    def test_values(self):
        assert WriteClass.HOT.value == "hot"
        assert WriteClass.COLD.value == "cold"
        assert WriteClass.MIXED.value == "mixed"


class TestWriteRecord:
    def test_deathtime_none_when_no_overwrite(self):
        r = WriteRecord(lba=0, size_bytes=4096, write_time=0.0)
        assert r.deathtime_ms is None

    def test_deathtime_computed(self):
        r = WriteRecord(lba=0, size_bytes=4096, write_time=1.0, overwrite_time=2.5)
        assert abs(r.deathtime_ms - 1500.0) < 1e-6

    def test_deathtime_zero(self):
        r = WriteRecord(lba=0, size_bytes=512, write_time=5.0, overwrite_time=5.0)
        assert r.deathtime_ms == 0.0


class TestWriteDeathtimeClassifier:
    def test_first_write_returns_none(self):
        clf = WriteDeathtimeClassifier(deathtime_threshold_ms=1000.0)
        result = clf.observe(lba=100, size_bytes=4096, timestamp=0.0)
        assert result is None

    def test_overwrite_classifies_hot(self):
        clf = WriteDeathtimeClassifier(deathtime_threshold_ms=5000.0)
        clf.observe(lba=100, size_bytes=4096, timestamp=0.0)
        result = clf.observe(lba=100, size_bytes=4096, timestamp=1.0)
        assert result == WriteClass.HOT

    def test_overwrite_classifies_cold(self):
        clf = WriteDeathtimeClassifier(deathtime_threshold_ms=500.0)
        clf.observe(lba=200, size_bytes=4096, timestamp=0.0)
        result = clf.observe(lba=200, size_bytes=4096, timestamp=10.0)
        assert result == WriteClass.COLD

    def test_multiple_lbas_independent(self):
        clf = WriteDeathtimeClassifier(deathtime_threshold_ms=2000.0)
        clf.observe(lba=0, size_bytes=4096, timestamp=0.0)
        clf.observe(lba=1, size_bytes=4096, timestamp=0.0)
        r0 = clf.observe(lba=0, size_bytes=4096, timestamp=0.5)
        r1 = clf.observe(lba=1, size_bytes=4096, timestamp=50.0)
        assert r0 == WriteClass.HOT
        assert r1 == WriteClass.COLD

    def test_classified_records_populated(self):
        clf = WriteDeathtimeClassifier()
        clf.observe(lba=10, size_bytes=512, timestamp=0.0)
        clf.observe(lba=10, size_bytes=512, timestamp=1.0)
        records = clf.classified_records()
        assert len(records) == 1
        assert records[0][0].lba == 10

    def test_flush_live_classifies_remaining(self):
        clf = WriteDeathtimeClassifier(deathtime_threshold_ms=1000.0)
        clf.observe(lba=5, size_bytes=4096, timestamp=0.0)
        flushed = clf.flush_live(timestamp=100.0)
        assert len(flushed) == 1
        assert flushed[0][1] == WriteClass.COLD

    def test_flush_live_clears_state(self):
        clf = WriteDeathtimeClassifier()
        clf.observe(lba=5, size_bytes=4096, timestamp=0.0)
        clf.flush_live(timestamp=1.0)
        assert len(clf._live) == 0


class TestSeparationScore:
    def _make_records(self):
        clf = WriteDeathtimeClassifier(deathtime_threshold_ms=1000.0)
        for i in range(5):
            clf.observe(lba=i, size_bytes=4096, timestamp=float(i))
            clf.observe(lba=i, size_bytes=4096, timestamp=float(i) + 0.1)
        for i in range(5, 10):
            clf.observe(lba=i, size_bytes=4096, timestamp=float(i))
            clf.observe(lba=i, size_bytes=4096, timestamp=float(i) + 100.0)
        return clf.classified_records()

    def test_compute_empty(self):
        result = SeparationScore.compute([])
        assert result["hot_count"] == 0
        assert result["cold_count"] == 0
        assert result["separation_score"] == 0.0

    def test_compute_counts(self):
        records = self._make_records()
        result = SeparationScore.compute(records)
        assert result["hot_count"] > 0
        assert result["cold_count"] > 0

    def test_compute_hot_fraction(self):
        records = self._make_records()
        result = SeparationScore.compute(records)
        assert 0.0 <= result["hot_fraction"] <= 1.0

    def test_compute_separation_score_range(self):
        records = self._make_records()
        result = SeparationScore.compute(records)
        assert 0.0 <= result["separation_score"] <= 1.0

    def test_compute_bytes(self):
        records = self._make_records()
        result = SeparationScore.compute(records)
        total = result["hot_bytes"] + result["cold_bytes"]
        assert total > 0


class TestWAFSample:
    def test_waf_computed(self):
        s = WAFSample(nand_written=200, host_written=100)
        assert s.waf == pytest.approx(2.0)

    def test_waf_zero_host(self):
        s = WAFSample(nand_written=100, host_written=0)
        assert s.waf == 0.0

    def test_waf_unity(self):
        s = WAFSample(nand_written=1000, host_written=1000)
        assert s.waf == pytest.approx(1.0)

    def test_defaults(self):
        s = WAFSample(nand_written=0, host_written=0)
        assert s.block_size == 4096
        assert s.pattern == "sequential"
