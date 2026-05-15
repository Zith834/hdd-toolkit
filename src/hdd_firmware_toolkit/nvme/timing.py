
from hdd_firmware_toolkit.nvme.admin import NVMeAdminCmd


class NVMeTimingSideChannel:
    """
    NVMe timing side channel analysis for covert communication and
    cross-VM information leakage via read latency contention.

    NVMe drives expose timing side channels through:
      1. Read contention: When one VM issues reads, another VM can detect
         latency spikes, establishing a covert channel (~1.5 kbit/s).
      2. HMB eviction: Host Memory Buffer eviction creates measurable
         timing differences (22 ms eviction, 8.3 kbit/s covert channel).
      3. Completion queue timing: Admin cmd completion timing reveals
         internal SSD state (garbage collection, wear leveling).

    Sources:
      - INVESTIGATION.md  -- "NDSS 2025 -- SSD Covert Timing Channels":
          NVMe read contention across VMs (1.5 kbit/s)
      - INVESTIGATION.md  -- "DIMVA 2025 -- HMB Timing Side Channel":
          22ms eviction, 8.3 kbit/s covert channel, UI redress
      - INVESTIGATION.md  -- "eNVMe -- NDSS 2025":
          DMA attack platform reference for timing analysis
    """

    # NVMe admin opcode used in timing measurements
    ADMIN_GET_LOG_PAGE = 0x02  # Get Log Page
    # HMB-related constants
    HMB_DESCRIPTOR_SIZE = 8  # bytes per HMB descriptor
    HMB_EVICTION_US = 22000  # ~22ms for full HMB eviction
    # Timing thresholds (microseconds)
    LATENCY_BASELINE_US = 50  # typical NVMe read latency
    CONTENTION_THRESHOLD_US = 200  # latency above this = contention detected
    COVERT_CHANNEL_BITRATE_BPS = 8300  # HMB side channel max bitrate

    @staticmethod
    def build_read_cmd(nsid: int = 1, slba: int = 0, nlb: int = 0, count: int = 1) -> NVMeAdminCmd:
        """Build an NVMe read command for timing measurement."""
        cmd = NVMeAdminCmd(opcode=0x02, nsid=nsid, data_len=512 * (nlb + 1))
        cmd.cdw10 = slba & 0xFFFFFFFF
        cmd.cdw11 = (slba >> 32) & 0xFFFFFFFF
        cmd.cdw12 = (nlb & 0xFFFF) | ((count & 0xFF) << 16)
        return cmd

    @staticmethod
    def estimate_read_latency(times_us: list[float]) -> dict:
        """
        Compute min/mean/median/max/stddev from a list of read latencies.
        Used to detect contention by comparing against a baseline.
        """
        if not times_us:
            return {}
        n = len(times_us)
        sorted_t = sorted(times_us)
        mean = sum(times_us) / n
        median = sorted_t[n // 2] if n % 2 else (sorted_t[n // 2 - 1] + sorted_t[n // 2]) / 2
        variance = sum((t - mean) ** 2 for t in times_us) / n
        return {
            "count": n,
            "min_us": min(times_us),
            "max_us": max(times_us),
            "mean_us": mean,
            "median_us": median,
            "stddev_us": variance**0.5,
            "p95_us": sorted_t[int(n * 0.95)],
            "p99_us": sorted_t[int(n * 0.99)],
        }

    @staticmethod
    def detect_content_contention(
        baseline: dict, sample: dict, threshold: float | None = None
    ) -> dict:
        """
        Compare a sample latency measurement against baseline.
        A significant increase in mean latency indicates contention
        from another process accessing the same namespace.
        """
        if not baseline or not sample:
            return {"contention_detected": False, "error": "insufficient data"}
        if threshold is None:
            threshold = NVMeTimingSideChannel.CONTENTION_THRESHOLD_US

        latency_delta = sample.get("mean_us", 0) - baseline.get("mean_us", 0)
        contention = (
            latency_delta > threshold or sample.get("max_us", 0) > baseline.get("p99_us", 0) * 2
        )
        bitrate = NVMeTimingSideChannel.COVERT_CHANNEL_BITRATE_BPS
        return {
            "contention_detected": contention,
            "latency_delta_us": latency_delta,
            "baseline_mean_us": baseline.get("mean_us", 0),
            "sample_mean_us": sample.get("mean_us", 0),
            "estimated_bitrate_bps": bitrate if contention else 0,
        }

    @staticmethod
    def hmB_eviction_sequence(n_pages: int = 256) -> list[int]:  # noqa: N802
        """
        Generate an HMB eviction sequence for timing analysis.
        Returns a list of page offsets to access in order to force
        HMB eviction and observe timing differences.
        """
        sequence = []
        stride = max(1, n_pages // 16)
        for round_idx in range(4):
            for i in range(0, n_pages, stride):
                sequence.append((i + round_idx * 7) % n_pages)
        return sequence

    @staticmethod
    def covert_channel_capacity(symbol_interval_us: float = 120) -> float:
        """
        Estimate covert channel capacity in bits/second.
        symbol_interval_us: time per symbol (default 120 us for 8.3 kbit/s).
        """
        return 1_000_000.0 / symbol_interval_us

    @staticmethod
    def ctrl_timing_analysis(completion_times_us: list[float]) -> dict:
        """
        Analyze NVMe completion queue timing for signs of internal
        SSD state changes (GC, wear leveling, thermal throttling).
        """
        if len(completion_times_us) < 10:
            return {"error": "need at least 10 samples"}
        stats = NVMeTimingSideChannel.estimate_read_latency(completion_times_us)
        # Detect clusters of slow completions indicating GC events
        gc_threshold = stats.get("mean_us", 0) * 3
        gc_events = [t for t in completion_times_us if t > gc_threshold]
        return {
            **stats,
            "gc_event_count": len(gc_events),
            "gc_event_ratio": len(gc_events) / len(completion_times_us),
            "gc_events_detected": len(gc_events) > 2,
        }
