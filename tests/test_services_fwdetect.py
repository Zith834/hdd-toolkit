import hashlib

from hdd_toolkit.firmware.detection import FirmwareDetection


def test_current_draw_anomaly_normal():
    result = FirmwareDetection.current_draw_anomaly(measured_ma=500, baseline_ma=500)
    assert "suspicious" in result
    assert result["suspicious"] is False


def test_current_draw_anomaly_detected():
    result = FirmwareDetection.current_draw_anomaly(measured_ma=600, baseline_ma=500)
    assert result["likely_modified"] is True


def test_timing_anomaly_normal():
    times = [100, 105, 98, 102, 101]
    result = FirmwareDetection.timing_anomaly(times, baseline_us=100)
    assert result["suspicious"] is False


def test_timing_anomaly_detected():
    times = [100, 105, 98, 500, 102, 101]
    result = FirmwareDetection.timing_anomaly(times, baseline_us=100)
    assert "suspicious" in result


def test_verify_checksums_empty():
    result = FirmwareDetection.verify_all_checksums(b"", vendor="unknown")
    assert isinstance(result, list)


def test_compare_against_known_good_unknown():
    result = FirmwareDetection.compare_against_known_good(firmware_hash="deadbeef")
    assert "matched" in result


def test_integrity_report():
    data = bytes(512)
    result = FirmwareDetection.integrity_report(data, vendor="unknown")
    assert "verdict" in result


def test_fw_readback_capability_hdd_blind():
    result = FirmwareDetection.fw_readback_capability(drive_type="hdd")
    assert result["capability"] == "blind"
    assert result["paths"] == []
    assert result["blind_reason"] != ""


def test_fw_readback_capability_hdd_vsc_partial():
    result = FirmwareDetection.fw_readback_capability(has_vsc_readback=True, drive_type="hdd")
    assert result["capability"] == "partial"
    assert "vsc_overlay_readback" in result["paths"]


def test_fw_readback_capability_ssd_full_jtag():
    result = FirmwareDetection.fw_readback_capability(has_jtag=True, drive_type="ssd")
    assert result["capability"] == "full"
    assert "jtag_spi_flash_dump" in result["paths"]
    assert "checksum_verification" in result["detection_methods"]


def test_fw_readback_capability_ssd_full_spi_clip():
    result = FirmwareDetection.fw_readback_capability(has_spi_clip=True, drive_type="ssd")
    assert result["capability"] == "full"
    assert "spi_clip_direct_read" in result["paths"]
    assert "known_good_hash_comparison" in result["detection_methods"]


def test_fw_readback_capability_hdd_jtag_partial():
    result = FirmwareDetection.fw_readback_capability(has_jtag=True, drive_type="hdd")
    assert result["capability"] == "partial"
    assert "jtag_memory_snapshot" in result["paths"]


def test_fw_readback_capability_always_has_side_channel():
    for drive_type in ("hdd", "ssd"):
        result = FirmwareDetection.fw_readback_capability(drive_type=drive_type)
        assert "timing_anomaly" in result["detection_methods"]
        assert "current_draw_anomaly" in result["detection_methods"]


def test_page_cache_integrity_probe_detects_mismatch():
    cached = b"A" * 512
    on_disk = b"B" * 512
    result = FirmwareDetection.page_cache_integrity_probe(
        lba=7,
        cached_data=cached,
        disk_read_fn=lambda _lba: on_disk,
        randomize_timing=False,
    )
    assert result["lba"] == 7
    assert result["cache_matches_disk"] is False
    assert result["deb_suspected"] is True
    assert result["confidence"] == 1.0


def test_bootloader_chain_verify_intact():
    second = b"second stage"
    third = b"third stage"
    known = {
        "second_bootloader": hashlib.sha256(second).hexdigest(),
        "third_bootloader": hashlib.sha256(third).hexdigest(),
    }
    result = FirmwareDetection.bootloader_chain_verify(
        mask_rom_hash="maskrom",
        second_bootloader=second,
        third_bootloader=third,
        known_good_hashes=known,
    )
    assert result["second_bootloader_ok"] is True
    assert result["third_bootloader_ok"] is True
    assert result["chain_intact"] is True
