import struct

from hdd_toolkit.ata.security import (
    ATAFrozenBypass,
    ATASecurityAccess,
    ATASecurityCmd,
    ATASecurityStatus,
    _build_password_sector,
)


# =============================================================================
# ATASecurityStatus.from_identify
# =============================================================================


def _make_identify(word128: int) -> bytes:
    buf = bytearray(512)
    struct.pack_into("<H", buf, 128 * 2, word128)
    return bytes(buf)


def test_security_supported_bit():
    status = ATASecurityStatus.from_identify(_make_identify(0x0001))
    assert status.security_supported is True


def test_security_not_supported():
    status = ATASecurityStatus.from_identify(_make_identify(0x0000))
    assert status.security_supported is False


def test_security_enabled_bit():
    status = ATASecurityStatus.from_identify(_make_identify(0x0003))
    assert status.security_enabled is True


def test_security_locked_bit():
    status = ATASecurityStatus.from_identify(_make_identify(0x0007))
    assert status.security_locked is True


def test_security_frozen_bit():
    status = ATASecurityStatus.from_identify(_make_identify(0x0009))
    assert status.security_frozen is True


def test_security_count_expired():
    status = ATASecurityStatus.from_identify(_make_identify(0x0011))
    assert status.security_count_expired is True


def test_enhanced_erase_supported():
    status = ATASecurityStatus.from_identify(_make_identify(0x0021))
    assert status.enhanced_erase_supported is True


def test_master_password_maximum():
    status = ATASecurityStatus.from_identify(_make_identify(0x0101))
    assert status.master_password_maximum is True


def test_raw_word_stored():
    status = ATASecurityStatus.from_identify(_make_identify(0xABCD))
    assert status.raw_word == 0xABCD


def test_short_identify_returns_defaults():
    status = ATASecurityStatus.from_identify(bytes(100))
    assert status.security_supported is False


# =============================================================================
# ATASecurityStatus computed properties
# =============================================================================


def test_can_unlock_when_enabled_not_frozen():
    s = ATASecurityStatus(security_enabled=True, security_frozen=False)
    assert s.can_unlock is True


def test_cannot_unlock_when_frozen():
    s = ATASecurityStatus(security_enabled=True, security_frozen=True)
    assert s.can_unlock is False


def test_can_freeze_when_not_frozen():
    s = ATASecurityStatus(security_frozen=False)
    assert s.can_freeze is True


def test_cannot_freeze_when_already_frozen():
    s = ATASecurityStatus(security_frozen=True)
    assert s.can_freeze is False


def test_can_erase_when_enabled_not_frozen():
    s = ATASecurityStatus(security_enabled=True, security_frozen=False)
    assert s.can_erase is True


# =============================================================================
# ATASecurityStatus.describe
# =============================================================================


def test_describe_not_supported():
    s = ATASecurityStatus(security_supported=False)
    assert "NOT supported" in s.describe()


def test_describe_frozen_appears_in_summary():
    s = ATASecurityStatus(security_supported=True, security_frozen=True)
    assert "FROZEN" in s.describe()


def test_describe_locked_appears_in_summary():
    s = ATASecurityStatus(security_supported=True, security_locked=True)
    assert "LOCKED" in s.describe()


def test_describe_master_pw_maximum():
    s = ATASecurityStatus(security_supported=True, master_password_maximum=True)
    assert "MAXIMUM" in s.describe()


# =============================================================================
# _build_password_sector
# =============================================================================


def test_password_sector_length():
    sector = _build_password_sector(master=False, password=b"testpass")
    assert len(sector) == 512


def test_user_password_control_word():
    sector = _build_password_sector(master=False, password=b"x")
    ctrl = struct.unpack_from("<H", sector, 0)[0]
    assert ctrl & 0x0001 == 0


def test_master_password_control_word():
    sector = _build_password_sector(master=True, password=b"x")
    ctrl = struct.unpack_from("<H", sector, 0)[0]
    assert ctrl & 0x0001 == 1


def test_password_stored_at_offset_2():
    pw = b"MyP4ssw0rd"
    sector = _build_password_sector(master=False, password=pw)
    assert sector[2:2 + len(pw)] == pw


def test_password_zero_padded_to_32():
    sector = _build_password_sector(master=False, password=b"abc")
    assert sector[5:34] == bytes(29)


def test_password_truncated_at_32():
    pw = b"A" * 64
    sector = _build_password_sector(master=False, password=pw)
    assert sector[2:34] == b"A" * 32


# =============================================================================
# ATASecurityCmd enum values
# =============================================================================


def test_set_password_opcode():
    assert ATASecurityCmd.SECURITY_SET_PASSWORD == 0xF1


def test_unlock_opcode():
    assert ATASecurityCmd.SECURITY_UNLOCK == 0xF2


def test_erase_prepare_opcode():
    assert ATASecurityCmd.SECURITY_ERASE_PREPARE == 0xF3


def test_erase_unit_opcode():
    assert ATASecurityCmd.SECURITY_ERASE_UNIT == 0xF4


def test_freeze_lock_opcode():
    assert ATASecurityCmd.SECURITY_FREEZE_LOCK == 0xF5


def test_disable_password_opcode():
    assert ATASecurityCmd.SECURITY_DISABLE_PASSWORD == 0xF6


# =============================================================================
# ATAFrozenBypass.analyse
# =============================================================================


def test_bypass_not_supported_drive():
    s = ATASecurityStatus(security_supported=False)
    result = ATAFrozenBypass.analyse(s)
    assert result["bypass_options"] == []


def test_bypass_frozen_options_include_s3():
    s = ATASecurityStatus(security_supported=True, security_frozen=True)
    result = ATAFrozenBypass.analyse(s)
    assert "s3_suspend_resume" in result["bypass_options"]


def test_bypass_frozen_options_include_usb_bridge():
    s = ATASecurityStatus(security_supported=True, security_frozen=True)
    result = ATAFrozenBypass.analyse(s)
    assert "usb_bridge_detour" in result["bypass_options"]


def test_bypass_locked_unfrozen_includes_brute_force():
    s = ATASecurityStatus(
        security_supported=True, security_enabled=True,
        security_locked=True, security_frozen=False
    )
    result = ATAFrozenBypass.analyse(s)
    assert "brute_force_unlock" in result["bypass_options"]


def test_bypass_frozen_field():
    s = ATASecurityStatus(security_supported=True, security_frozen=True)
    result = ATAFrozenBypass.analyse(s)
    assert result["frozen"] is True


def test_bypass_not_frozen_field():
    s = ATASecurityStatus(security_supported=True, security_frozen=False)
    result = ATAFrozenBypass.analyse(s)
    assert result["frozen"] is False
