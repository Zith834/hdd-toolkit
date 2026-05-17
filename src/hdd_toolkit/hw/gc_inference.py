from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from hdd_toolkit.nvme.waf import WAFMeter


@dataclass
class GCSweepPoint:
    """
    A WAF measurement at a specific block size for GC unit inference.

    Sources:
      - Lee et al., "SSD-level Write Amplification Measurement", VLDB vol.19
        p.1469 (2026), Section 5.3: GC unit inference without ZNS.
    """

    block_size: int
    waf: float
    nand_delta: int
    host_delta: int


class GCUnitInferrer:
    """
    Infers the GC stripe (erase unit) size of an NVMe SSD without ZNS
    by monitoring WAF inflection points across varying block sizes.

    Algorithm:
      1. Fill the drive to a target utilization with sequential writes.
      2. For each candidate block size, issue sequential writes of that
         size, snapshot OCP C1 WAF counters before and after, record
         delta WAF.
      3. Estimate the GC stripe size as the smallest block size where
         WAF drops sharply (below a threshold), indicating that writes
         are now GC-stripe aligned.

    In a live setting *snap_func* wraps NVMeDevice.send(); for tests
    it accepts a callable mock.

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 5.3.
      - INVESTIGATION.md: SSD GC and WAF measurement techniques.
    """

    DEFAULT_BLOCK_SIZES: ClassVar[list[int]] = [4096, 8192, 16384, 32768, 65536, 131072, 262144]
    WAF_ALIGNED_THRESHOLD = 1.1

    def __init__(self, capacity_lba: int = 0, lba_size: int = 4096) -> None:
        self.capacity_lba = capacity_lba
        self.lba_size = lba_size
        self._meter = WAFMeter()

    @staticmethod
    def build_fill_sequence(
        capacity_lba: int,
        fill_ratio: float = 0.80,
        block_size_lba: int = 8,
    ) -> list[tuple[int, int]]:
        """
        Generate a sequential LBA write sequence to fill the drive to
        *fill_ratio* of its capacity.

        Returns a list of (slba, nlb) tuples suitable for issuing NVMe
        Write commands.  *nlb* is number-of-blocks minus 1.

        Args:
            capacity_lba:    Total drive capacity in logical blocks.
            fill_ratio:      Fraction of capacity to fill (0.0-1.0).
            block_size_lba:  Write granularity in logical blocks.
        """
        if capacity_lba <= 0 or not (0.0 < fill_ratio <= 1.0):
            return []
        target = int(capacity_lba * fill_ratio)
        sequence = []
        lba = 0
        while lba < target:
            nlb = min(block_size_lba, target - lba) - 1
            sequence.append((lba, nlb))
            lba += nlb + 1
        return sequence

    def sweep(
        self,
        snap_func,
        block_sizes: list[int] | None = None,
    ) -> list[GCSweepPoint]:
        """
        Sweep over block sizes, recording WAF at each step.

        Args:
            snap_func: callable(block_size: int) -> (before_buf: bytes, after_buf: bytes)
                       where each buf is a 512-byte OCP C1 SMART extended log snapshot.
            block_sizes: write sizes in bytes to test; defaults to DEFAULT_BLOCK_SIZES.

        Returns:
            List of GCSweepPoint sorted by block_size ascending.
        """
        if block_sizes is None:
            block_sizes = self.DEFAULT_BLOCK_SIZES

        points: list[GCSweepPoint] = []
        for bs in sorted(block_sizes):
            before_buf, after_buf = snap_func(bs)
            self._meter.snapshot_before(before_buf)
            self._meter.snapshot_after(after_buf)
            delta = self._meter.delta_waf()
            points.append(
                GCSweepPoint(
                    block_size=bs,
                    waf=delta.get("waf", 0.0),
                    nand_delta=delta.get("delta_nand_written", 0),
                    host_delta=delta.get("delta_host_written", 0),
                )
            )
        return points

    @staticmethod
    def estimate_gc_unit(waf_by_size: list[GCSweepPoint]) -> int:
        """
        Return the estimated GC stripe size in bytes.

        Finds the smallest block_size where WAF drops below
        WAF_ALIGNED_THRESHOLD (1.1), indicating GC-stripe alignment.
        Returns 0 if no aligned point is found.

        Args:
            waf_by_size: list of GCSweepPoint from sweep().
        """
        for point in sorted(waf_by_size, key=lambda p: p.block_size):
            if 0 < point.waf < GCUnitInferrer.WAF_ALIGNED_THRESHOLD:
                return point.block_size
        return 0
