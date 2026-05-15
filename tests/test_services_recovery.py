from hdd_toolkit.hw.data_recovery import ReadRetryResult, SATADataRecoveryOps


def test_read_retry_escalation_fails_without_hardware():
    result = SATADataRecoveryOps.read_retry_escalation(
        drive_path="/dev/null", lba=0,
        levels=["pio"], max_attempts_per_level=1,
    )
    assert result.success is False


def test_smart_quick_test():
    result = SATADataRecoveryOps.smart_quick_test("/dev/null")
    assert result["test_type"] == "short"
    assert result["drive"] == "/dev/null"


def test_read_native_max():
    result = SATADataRecoveryOps.read_native_max("/dev/null")
    assert result == 0


def test_identify_device():
    result = SATADataRecoveryOps.identify_device("/dev/null")
    assert "serial" in result
    assert "firmware" in result
    assert "model" in result
    assert "lba48_supported" in result


def test_defective_sector_pattern():
    pattern = SATADataRecoveryOps.defective_sector_pattern_offset(lba=0x1000, sector_size=512)
    assert len(pattern) == 512
    assert pattern[0:4] == b"\xEF\xBE\xAD\xDE"


def test_build_read_cdb_pio():
    cdb = SATADataRecoveryOps.build_read_cdb(lba=0x100, sector_count=1, protocol="pio")
    assert len(cdb) == 16
    assert cdb[0] == 0x85


def test_build_read_cdb_dma():
    cdb = SATADataRecoveryOps.build_read_cdb(lba=0x100, sector_count=1, protocol="dma")
    assert cdb is not None


def test_read_retry_defaults():
    result = SATADataRecoveryOps.read_retry_escalation(
        drive_path="/dev/null", lba=0,
        max_attempts_per_level=1,
    )
    assert isinstance(result, ReadRetryResult)
