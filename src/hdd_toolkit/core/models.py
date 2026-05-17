from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class WriteClass(Enum):
    """
    Lifecycle classification for a written LBA range.

    Sources:
      - Lee et al., "SSD-level Write Amplification Measurement", VLDB vol.19
        p.1469 (2026), Section 4: deathtime-based write classification.
    """

    HOT = "hot"
    COLD = "cold"
    MIXED = "mixed"


@dataclass
class WriteRecord:
    """
    A single host write event tracked for deathtime classification.

    deathtime_ms is derived as (overwrite_time - write_time) when both
    timestamps are known, otherwise None until the LBA is overwritten.

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 4.
    """

    lba: int
    size_bytes: int
    write_time: float
    overwrite_time: float | None = None

    @property
    def deathtime_ms(self) -> float | None:
        if self.overwrite_time is None:
            return None
        return (self.overwrite_time - self.write_time) * 1000.0


class WriteDeathtimeClassifier:
    """
    Classifies host writes as HOT or COLD based on LBA reuse intervals.

    Maintains a live map of (lba -> WriteRecord) updated on each write
    observation.  When a previously-written LBA is overwritten the
    deathtime is recorded and the entry is classified according to
    deathtime_threshold_ms.

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 4: deathtime model.
    """

    def __init__(self, deathtime_threshold_ms: float = 60_000.0) -> None:
        self.deathtime_threshold_ms = deathtime_threshold_ms
        self._live: dict[int, WriteRecord] = {}
        self._classified: list[tuple[WriteRecord, WriteClass]] = []

    def observe(self, lba: int, size_bytes: int, timestamp: float) -> WriteClass | None:
        """
        Record a write at *lba* with the given *timestamp* (seconds).

        If this LBA was previously written, closes the previous record,
        computes its deathtime, and returns its WriteClass.  Otherwise
        records a new live entry and returns None.
        """
        if lba in self._live:
            prev = self._live[lba]
            prev.overwrite_time = timestamp
            cls = self._classify_record(prev)
            self._classified.append((prev, cls))
            self._live[lba] = WriteRecord(lba, size_bytes, timestamp)
            return cls
        self._live[lba] = WriteRecord(lba, size_bytes, timestamp)
        return None

    def _classify_record(self, record: WriteRecord) -> WriteClass:
        dt = record.deathtime_ms
        if dt is None:
            return WriteClass.COLD
        return WriteClass.HOT if dt < self.deathtime_threshold_ms else WriteClass.COLD

    def classified_records(self) -> list[tuple[WriteRecord, WriteClass]]:
        """Return all records whose deathtime has been resolved."""
        return list(self._classified)

    def flush_live(self, timestamp: float) -> list[tuple[WriteRecord, WriteClass]]:
        """
        Close all open (un-overwritten) live records at *timestamp*.

        Returns list of (WriteRecord, WriteClass) for each flushed entry.
        Writes that were never overwritten are classified as COLD.
        """
        result = []
        for lba, record in list(self._live.items()):
            record.overwrite_time = timestamp
            cls = self._classify_record(record)
            self._classified.append((record, cls))
            result.append((record, cls))
        self._live.clear()
        return result


class SeparationScore:
    """
    Measures the WAF-reduction potential from separating HOT vs COLD writes
    onto different FDP reclaim unit handles (RUHs).

    A high separation score indicates that the workload has well-defined
    short-lived and long-lived data streams that would benefit from FDP
    placement hints.

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 4: write separation.
    """

    @staticmethod
    def compute(records: list[tuple[WriteRecord, WriteClass]]) -> dict:
        """
        Compute separation statistics from a list of (WriteRecord, WriteClass).

        Returns:
            hot_count, cold_count, hot_bytes, cold_bytes,
            hot_fraction (fraction of write traffic classified HOT),
            separation_score (0-1: higher is more separable),
            mean_hot_deathtime_ms, mean_cold_deathtime_ms.
        """
        if not records:
            return {
                "hot_count": 0,
                "cold_count": 0,
                "hot_bytes": 0,
                "cold_bytes": 0,
                "hot_fraction": 0.0,
                "separation_score": 0.0,
                "mean_hot_deathtime_ms": 0.0,
                "mean_cold_deathtime_ms": 0.0,
            }
        hot = [(r, c) for r, c in records if c == WriteClass.HOT]
        cold = [(r, c) for r, c in records if c == WriteClass.COLD]

        hot_bytes = sum(r.size_bytes for r, _ in hot)
        cold_bytes = sum(r.size_bytes for r, _ in cold)
        total_bytes = hot_bytes + cold_bytes

        hot_fraction = hot_bytes / total_bytes if total_bytes else 0.0

        hot_dts = [r.deathtime_ms for r, _ in hot if r.deathtime_ms is not None]
        cold_dts = [r.deathtime_ms for r, _ in cold if r.deathtime_ms is not None]

        mean_hot = sum(hot_dts) / len(hot_dts) if hot_dts else 0.0
        mean_cold = sum(cold_dts) / len(cold_dts) if cold_dts else 0.0

        if mean_cold > 0 and mean_hot >= 0:
            ratio = mean_cold / (mean_hot + 1.0)
            score = min(1.0, ratio / 100.0)
        else:
            score = 0.0

        return {
            "hot_count": len(hot),
            "cold_count": len(cold),
            "hot_bytes": hot_bytes,
            "cold_bytes": cold_bytes,
            "hot_fraction": hot_fraction,
            "separation_score": score,
            "mean_hot_deathtime_ms": mean_hot,
            "mean_cold_deathtime_ms": mean_cold,
        }


@dataclass
class WAFSample:
    """
    A single write amplification factor (WAF) measurement.

    nand_written and host_written are in 512-byte units (matching the
    NVMe SMART log convention where 1 unit = 1000 * 512 bytes written).

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 3.
      - NVMe 2.0 Base Specification, Section 5.14.1.2 (SMART log).
    """

    nand_written: int
    host_written: int
    block_size: int = 4096
    queue_depth: int = 1
    pattern: str = "sequential"
    waf: float = field(init=False)

    def __post_init__(self) -> None:
        self.waf = (
            self.nand_written / self.host_written if self.host_written > 0 else 0.0
        )
