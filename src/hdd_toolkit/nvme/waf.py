from __future__ import annotations

import struct
from dataclasses import dataclass

from hdd_toolkit.nvme.admin import NVMeAdminCmd, NVMeAdminPassthrough
from hdd_toolkit.nvme.timing import NVMeTimingSideChannel


@dataclass
class WAFProfile:
    """
    A WAF measurement associated with a specific write workload pattern.

    Sources:
      - Lee et al., "SSD-level Write Amplification Measurement", VLDB vol.19
        p.1469 (2026), Figure 7: WAF vs. block size curves.
    """

    pattern: str
    waf: float
    queue_depth: int
    block_size: int
    nand_written: int = 0
    host_written: int = 0


class WAFMeter:
    """
    Host-vs-device WAF measurement using OCP SMART extended log page 0xC1
    and standard SMART log page 0x02.

    WAF = NAND bytes written / host bytes written.

    Two snapshot points are taken (before / after a workload window), and
    the delta is used so that background wear-levelling traffic does not
    inflate the result.

    Log page 0xC1 layout (OCP Cloud SSD Spec, 512-byte read):
      offset 0x00  8 bytes: physical_media_units_written lo (LE u64)
      offset 0x08  8 bytes: physical_media_units_written hi (LE u64) [128-bit]
      offset 0x10  8 bytes: host_written_units lo (LE u64)
      offset 0x18  8 bytes: host_written_units hi (LE u64) [128-bit]

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 3: WAF measurement.
      - OCP NVMe Cloud SSD Spec v2.5, Section 4.4: SMART extended log 0xC1.
      - NVMe 2.0 Base Specification, Section 5.14.1.2 (log 0x02).
    """

    OCP_LOG_C1 = 0xC1
    OCP_LOG_C1_SIZE = 512

    def __init__(self) -> None:
        self._snap_before: dict = {}
        self._snap_after: dict = {}

    @staticmethod
    def build_ocp_waf_log_cmd(nsid: int = 0xFFFFFFFF) -> NVMeAdminCmd:
        """Build GET LOG PAGE for OCP SMART extended log (0xC1, 512 bytes)."""
        return NVMeAdminPassthrough.get_log_page(
            log_id=WAFMeter.OCP_LOG_C1,
            nsid=nsid,
            size=WAFMeter.OCP_LOG_C1_SIZE,
        )

    @staticmethod
    def parse_ocp_waf_fields(data: bytes) -> dict:
        """
        Parse the OCP SMART extended log (0xC1) for WAF-relevant counters.

        Returns nand_written (128-bit) and host_written (128-bit) as Python
        ints, plus a pre-computed waf float.
        """
        if len(data) < 32:
            return {"error": "data too short for OCP C1 log"}
        nand_lo, nand_hi = struct.unpack_from("<QQ", data, 0x00)
        host_lo, host_hi = struct.unpack_from("<QQ", data, 0x10)
        nand_written = nand_lo | (nand_hi << 64)
        host_written = host_lo | (host_hi << 64)
        waf = nand_written / host_written if host_written > 0 else 0.0
        return {
            "nand_written": nand_written,
            "host_written": host_written,
            "waf": waf,
        }

    @staticmethod
    def compute_waf(nand_written: int, host_written: int) -> float:
        """Compute WAF = nand_written / host_written."""
        if host_written <= 0:
            return 0.0
        return nand_written / host_written

    def snapshot_before(self, data: bytes) -> None:
        """Record the pre-workload OCP C1 log snapshot."""
        self._snap_before = self.parse_ocp_waf_fields(data)

    def snapshot_after(self, data: bytes) -> None:
        """Record the post-workload OCP C1 log snapshot."""
        self._snap_after = self.parse_ocp_waf_fields(data)

    def delta_waf(self) -> dict:
        """
        Compute WAF from the delta between two snapshots.

        Uses the difference in NAND-written and host-written counters so
        that accumulated historical traffic does not bias the result.
        """
        if "error" in self._snap_before or "error" in self._snap_after:
            return {"error": "invalid snapshot data"}
        d_nand = self._snap_after["nand_written"] - self._snap_before["nand_written"]
        d_host = self._snap_after["host_written"] - self._snap_before["host_written"]
        waf = self.compute_waf(d_nand, d_host)
        return {
            "delta_nand_written": d_nand,
            "delta_host_written": d_host,
            "waf": waf,
        }


class WorkloadClassifier:
    """
    Cross-references NVMe timing side-channel statistics with a WAF sample
    to label the active workload phase.

    Classification rules (heuristic):
      - If p99 latency > 5 * baseline mean  ->  GC-heavy / mixed
      - If WAF < 1.05 and block_size >= 65536  ->  sequential
      - If WAF > 3.0 or block_size <= 4096  ->  random_4k
      - Otherwise  ->  mixed

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 5: workload profiling.
      - INVESTIGATION.md: NVMe timing side-channel analysis.
    """

    @staticmethod
    def classify(latency_stats: dict, waf: float, block_size: int = 4096) -> WAFProfile:
        """
        Return a WAFProfile labelled with the inferred workload pattern.

        Args:
            latency_stats: output of NVMeTimingSideChannel.estimate_read_latency().
            waf: measured WAF float.
            block_size: write block size in bytes.
        """
        mean_us = latency_stats.get("mean_us", 0.0)
        p99_us = latency_stats.get("p99_us", 0.0)

        gc_active = p99_us > mean_us * 5 if mean_us > 0 else False

        if gc_active:
            pattern = "mixed"
        elif waf < 1.05 and block_size >= 65536:
            pattern = "sequential"
        elif waf > 3.0 or block_size <= 4096:
            pattern = "random_4k"
        else:
            pattern = "mixed"

        return WAFProfile(
            pattern=pattern,
            waf=waf,
            queue_depth=1,
            block_size=block_size,
        )

    @staticmethod
    def classify_from_times(times_us: list[float], waf: float, block_size: int = 4096) -> WAFProfile:
        """Convenience wrapper: compute latency stats then classify."""
        stats = NVMeTimingSideChannel.estimate_read_latency(times_us)
        return WorkloadClassifier.classify(stats, waf, block_size)


@dataclass
class WAFSweepPoint:
    """A single point on the WAF-vs-block-size curve."""

    block_size: int
    waf: float
    nand_delta: int
    host_delta: int


def waf_sweep(
    snap_func,
    block_sizes: list[int] | None = None,
) -> list[WAFSweepPoint]:
    """
    Vary block size across *block_sizes* and record WAF at each step.

    *snap_func(block_size)* must return a tuple of two 512-byte OCP C1
    log buffers: (before_buf, after_buf).  In a live setting this would
    perform the actual writes between snapshots; in testing it accepts a
    callable mock.

    Generates the WAF-vs-block-size curve described in Lee et al.
    Figure 7 (VLDB vol.19 p.1469, 2026).

    Args:
        snap_func: callable(block_size: int) -> (bytes, bytes)
        block_sizes: list of block sizes in bytes (default 4K..128K)

    Returns:
        List of WAFSweepPoint in block_size order.
    """
    if block_sizes is None:
        block_sizes = [4096, 8192, 16384, 32768, 65536, 131072]

    meter = WAFMeter()
    results: list[WAFSweepPoint] = []
    for bs in sorted(block_sizes):
        before_buf, after_buf = snap_func(bs)
        meter.snapshot_before(before_buf)
        meter.snapshot_after(after_buf)
        delta = meter.delta_waf()
        results.append(
            WAFSweepPoint(
                block_size=bs,
                waf=delta.get("waf", 0.0),
                nand_delta=delta.get("delta_nand_written", 0),
                host_delta=delta.get("delta_host_written", 0),
            )
        )
    return results
