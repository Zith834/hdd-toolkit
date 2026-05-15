from hdd_firmware_toolkit.firmware.detection import FirmwareDetection


def test_current_draw_anomaly_normal():
    result = FirmwareDetection.current_draw_anomaly(
        measured_ma=500, baseline_ma=500
    )
    assert "suspicious" in result
    assert result["suspicious"] is False


def test_current_draw_anomaly_detected():
    result = FirmwareDetection.current_draw_anomaly(
        measured_ma=600, baseline_ma=500
    )
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
    result = FirmwareDetection.compare_against_known_good(
        firmware_hash="deadbeef"
    )
    assert "matched" in result


def test_integrity_report():
    data = bytes(512)
    result = FirmwareDetection.integrity_report(data, vendor="unknown")
    assert "verdict" in result
