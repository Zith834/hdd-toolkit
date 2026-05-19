import hashlib
import random
import struct
import time
from collections.abc import Callable
from typing import ClassVar

from hdd_toolkit.firmware.patcher import FirmwarePatcher


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
    def fw_readback_capability(
        has_jtag: bool = False,
        has_spi_clip: bool = False,
        has_vsc_readback: bool = False,
        drive_type: str = "hdd",
    ) -> dict:
        """
        Probe whether the attached drive supports read-back of its firmware
        area via any known path, and return a structured verdict.

        For most spinning-rust HDDs the firmware resides in service tracks
        on the platter, which are not accessible via any host interface.
        This is not an implementation gap but a design constraint: as the
        GReAT researchers noted, "for most hard drives there are functions
        to write into the hardware firmware area but no functions to read
        it back."

        SSDs store firmware in SPI NOR flash which IS readable via a
        JTAG-connected SPI clip or by attaching directly to the flash chip.

        Parameters
        ----------
        has_jtag        : True if JTAG/OpenOCD is available and responds
        has_spi_clip    : True if a SPI flash clip is attached (SSD only)
        has_vsc_readback: True if the drive responds to VSC read-overlay
                          commands that expose firmware module data
        drive_type      : "hdd" (spinning rust) or "ssd" (NAND/NOR flash)

        Returns
        -------
        dict with keys:
          capability  -- "blind" | "partial" | "full"
          paths       -- list of available read-back methods
          blind_reason -- explanation when capability == "blind"
          detection_methods -- list of applicable detection methods
        """
        paths: list[str] = []
        detection_methods: list[str] = ["timing_anomaly", "current_draw_anomaly"]

        if has_jtag:
            if drive_type == "ssd":
                paths.append("jtag_spi_flash_dump")
                detection_methods.append("checksum_verification")
            else:
                paths.append("jtag_memory_snapshot")

        if has_spi_clip and drive_type == "ssd":
            paths.append("spi_clip_direct_read")
            detection_methods.append("checksum_verification")
            detection_methods.append("known_good_hash_comparison")

        if has_vsc_readback:
            paths.append("vsc_overlay_readback")
            detection_methods.append("vsc_overlay_comparison")

        if drive_type == "hdd" and not has_jtag and not has_vsc_readback:
            capability = "blind"
            blind_reason = (
                "HDD firmware lives in service tracks on the platter; "
                "no host-accessible read path exists without JTAG or "
                "vendor-specific service commands"
            )
        elif paths:
            full_read_paths = {"jtag_spi_flash_dump", "spi_clip_direct_read"}
            capability = "full" if any(p in full_read_paths for p in paths) else "partial"
            blind_reason = ""
        else:
            capability = "blind"
            blind_reason = (
                "No read-back path available; use timing and current-draw "
                "side-channels for detection"
            )

        return {
            "drive_type": drive_type,
            "capability": capability,
            "paths": paths,
            "blind_reason": blind_reason,
            "detection_methods": detection_methods,
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

    @staticmethod
    def page_cache_integrity_probe(
        lba: int,
        cached_data: bytes,
        disk_read_fn: Callable[[int], bytes],
        randomize_timing: bool = True,
    ) -> dict:
        """
        Detect DEB-style replacement by comparing cache copy vs direct disk read.
        """
        if randomize_timing:
            time.sleep(random.uniform(0.0, 0.05))

        disk_data = disk_read_fn(lba)
        cache_hash = hashlib.sha256(cached_data).hexdigest()
        disk_hash = hashlib.sha256(disk_data).hexdigest()
        cache_matches_disk = cached_data == disk_data
        deb_suspected = not cache_matches_disk

        return {
            "lba": lba,
            "cache_matches_disk": cache_matches_disk,
            "deb_suspected": deb_suspected,
            "cache_hash": cache_hash,
            "disk_hash": disk_hash,
            "timing_randomized": randomize_timing,
            "confidence": 1.0 if deb_suspected else 0.0,
        }

    @staticmethod
    def bootloader_chain_verify(
        mask_rom_hash: str,
        second_bootloader: bytes,
        third_bootloader: bytes,
        known_good_hashes: dict[str, str],
    ) -> dict:
        """
        Verify boot chain stages anchored in mask ROM root of trust.
        """
        second_hash = hashlib.sha256(second_bootloader).hexdigest()
        third_hash = hashlib.sha256(third_bootloader).hexdigest()
        second_ok = second_hash == known_good_hashes.get("second_bootloader")
        third_ok = third_hash == known_good_hashes.get("third_bootloader")

        expected_mask_rom = known_good_hashes.get("mask_rom")
        mask_rom_ok = expected_mask_rom is None or mask_rom_hash == expected_mask_rom

        return {
            "mask_rom_hash": mask_rom_hash,
            "second_bootloader_hash": second_hash,
            "second_bootloader_ok": second_ok,
            "third_bootloader_hash": third_hash,
            "third_bootloader_ok": third_ok,
            "chain_intact": mask_rom_ok and second_ok and third_ok,
            "root_of_trust": "mask_rom",
            "attack_surface": (
                "Mask ROM is hardware-rooted; second-stage flash and third-stage "
                "service-area firmware remain primary mutable targets."
            ),
        }
