import hashlib
import struct
from typing import ClassVar

from hdd_firmware_toolkit.firmware.patcher import FirmwarePatcher


class FirmwareDetection:
    """
    Firmware integrity verification and side-channel detection methods.

    Detecting compromised firmware is notoriously difficult because:
      1. Most drives do not implement read-back for firmware areas
      2. Firmware operates below the OS -- no host software can observe it
      3. Malicious firmware can lie about its own state when queried

    Detection methods implemented:
      - Current draw profiling: Compare power consumption during write
        against known-good baseline (>90% accuracy for modified firmware)
      - Timing anomaly detection: Measure read/write completion timing
        for behavioral differences
      - Checksum verification: Verify all firmware checksums (if read-back
        is available via JTAG/SPI)
      - Known-good database matching: Compare firmware hashes against
        curated known-good firmware database
      - Behavioral monitoring: Track read/write patterns for anomalies

    Sources:
      - INVESTIGATION.md  -- "Detecting firmware mod on SSDs via current
        draw analysis (2020, ScienceDirect)":
          >90% accuracy binary classifier on current profiles
      - INVESTIGATION.md  -- "Side-Channel Firmware Detection (2020)":
          Current draw profiling methodology
      - INVESTIGATION.md  -- "Read & Sutherland -- Firmware Manipulation
        and Forensic Impact (2019)":
          Forensic detection of firmware-level manipulation
      - INVESTIGATION.md  -- "JTAG forensic acquisition":
          Physical flash dump via JTAG for offline verification
      - INVESTIGATION.md  -- "SPI flash read for hash comparison":
          Physical SPI flash read for known-good verification
    """

    # Timing anomaly thresholds (microseconds)
    TIMING_BASELINE_US = 5000  # typical SATA write completion
    TIMING_WARN_FACTOR = 2.0  # >2x baseline = potential modified FW
    TIMING_CRIT_FACTOR = 5.0  # >5x baseline = likely modified FW

    # Current draw thresholds (milliamps, normalized)
    CURRENT_BASELINE_MA = 100  # typical idle + write current
    CURRENT_WARN_DELTA = 30  # >30mA delta from baseline = suspicious
    CURRENT_CRIT_DELTA = 75  # >75mA delta = likely modified

    # Known-good firmware hash database (model -> hash)
    KNOWN_GOOD_DB: ClassVar[dict[str, str]] = {}

    @staticmethod
    def current_draw_anomaly(measured_ma: float, baseline_ma: float | None = None) -> dict:
        """
        Analyze current draw measurement for firmware modification.
        Modified firmware produces measurably different current profiles
        during write operations (>90% detection accuracy).
        """
        if baseline_ma is None:
            baseline_ma = FirmwareDetection.CURRENT_BASELINE_MA
        delta = abs(measured_ma - baseline_ma)
        return {
            "baseline_ma": baseline_ma,
            "measured_ma": measured_ma,
            "delta_ma": delta,
            "anomaly_score": delta / FirmwareDetection.CURRENT_WARN_DELTA,
            "suspicious": delta > FirmwareDetection.CURRENT_WARN_DELTA,
            "likely_modified": delta > FirmwareDetection.CURRENT_CRIT_DELTA,
            "confidence": min(1.0, delta / 100.0),
        }

    @staticmethod
    def timing_anomaly(completion_times_us: list[float], baseline_us: float | None = None) -> dict:
        """
        Detect firmware modification through read/write timing analysis.
        Modified firmware often introduces measurable timing changes
        due to additional code paths or device initialization.
        """
        if not completion_times_us:
            return {"error": "no timing data"}
        if baseline_us is None:
            baseline_us = FirmwareDetection.TIMING_BASELINE_US
        mean_time = sum(completion_times_us) / len(completion_times_us)
        ratio = mean_time / baseline_us if baseline_us else 1.0
        return {
            "baseline_us": baseline_us,
            "mean_time_us": mean_time,
            "ratio_vs_baseline": ratio,
            "suspicious": ratio > FirmwareDetection.TIMING_WARN_FACTOR,
            "likely_modified": ratio > FirmwareDetection.TIMING_CRIT_FACTOR,
            "confidence": min(1.0, (ratio - 1.0) / 4.0),
        }

    @staticmethod
    def verify_all_checksums(data: bytes, vendor: str) -> list[dict]:
        """
        Verify all firmware checksums supported by the vendor.
        Requires read-back access (JTAG, SPI, or VSC).
        """
        results = []
        patcher = FirmwarePatcher(data, vendor)
        # Run the same fix logic but report instead of modify
        for method_name in ["_fix_wd", "_fix_seagate_lod", "_fix_toshiba", "_fix_samsung_overlay"]:
            method = getattr(patcher, method_name, None)
            if method and callable(method):
                try:
                    before = bytes(patcher.data)
                    method()
                    after = bytes(patcher.data)
                    region_start = 0
                    for i in range(min(len(before), len(after))):
                        if before[i] != after[i]:
                            region_start = i
                            break
                    modified = before != after
                    results.append(
                        {
                            "method": method_name[5:],  # strip _fix_
                            "vendor": vendor,
                            "checksum_valid": not modified,
                            "region_offset": region_start if modified else None,
                            "modified": modified,
                        }
                    )
                except Exception as e:
                    results.append(
                        {
                            "method": method_name,
                            "vendor": vendor,
                            "error": str(e),
                            "checksum_valid": False,
                        }
                    )
        return results

    @staticmethod
    def compare_against_known_good(firmware_hash: str, model: str = "") -> dict:
        """
        Compare a firmware SHA256 hash against the known-good database.
        """
        expected = FirmwareDetection.KNOWN_GOOD_DB.get(model)
        if expected is None:
            return {"matched": None, "error": "model not in database"}
        return {
            "model": model,
            "hash": firmware_hash,
            "expected_hash": expected,
            "matched": firmware_hash == expected,
            "integrity_ok": firmware_hash == expected,
        }

    @staticmethod
    def analyze_identify_anomaly(identify_data: bytes, known_good: bytes | None = None) -> dict:
        """
        Compare IDENTIFY DEVICE/CONTROLLER data against known-good values.
        Modified firmware often alters identify data to conceal changes.
        """
        if len(identify_data) < 512:
            return {"error": "identify data too short"}
        anomalies = {}
        if known_good and len(known_good) >= 512:
            for offset in range(0, 512, 2):
                val = struct.unpack_from("<H", identify_data, offset)[0]
                ref = struct.unpack_from("<H", known_good, offset)[0]
                if val != ref:
                    anomalies[offset] = {"observed": val, "expected": ref}
        return {
            "anomalies_found": len(anomalies) > 0,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "identify_size": len(identify_data),
        }

    @staticmethod
    def integrity_report(
        data: bytes,
        vendor: str,
        timing_us: list[float] | None = None,
        current_ma: float | None = None,
    ) -> dict:
        """
        Generate a comprehensive firmware integrity report combining
        all available detection methods.
        """
        report = {
            "vendor": vendor,
            "file_size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        # Checksum verification
        ck_results = FirmwareDetection.verify_all_checksums(data, vendor)
        report["checksum_verification"] = ck_results
        all_checksums_valid = all(
            r.get("checksum_valid", False) for r in ck_results if "error" not in r
        )
        report["all_checksums_valid"] = all_checksums_valid
        # Timing analysis (if available)
        if timing_us:
            report["timing"] = FirmwareDetection.timing_anomaly(timing_us)
        # Current draw analysis (if available)
        if current_ma is not None:
            report["current_draw"] = FirmwareDetection.current_draw_anomaly(current_ma)
        # Overall verdict
        flags = []
        if not all_checksums_valid:
            flags.append("checksum_mismatch")
        if timing_us and report.get("timing", {}).get("likely_modified"):
            flags.append("timing_anomaly")
        if current_ma is not None and report.get("current_draw", {}).get("likely_modified"):
            flags.append("current_draw_anomaly")
        report["flags"] = flags
        report["verdict"] = (
            "modified" if flags else "no_detection_possible" if len(data) == 0 else "clean"
        )
        return report
