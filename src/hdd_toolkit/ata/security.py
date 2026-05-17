"""ATA Security Feature Set: status parsing and command builders."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from hdd_toolkit.ata.commands import ATADevice


# =============================================================================
# ATA Security command opcodes  (ACS-3, Section 7.44 -- 7.49)
# =============================================================================


class ATASecurityCmd(IntEnum):
    """
    ATA command codes for the Security Feature Set.

    Sources:
      - ACS-3, Table 67: Command Codes.
      - ATA/ATAPI-7 Volume 1, Section 6.17: Security Feature Set.
    """

    SECURITY_SET_PASSWORD = 0xF1
    SECURITY_UNLOCK = 0xF2
    SECURITY_ERASE_PREPARE = 0xF3
    SECURITY_ERASE_UNIT = 0xF4
    SECURITY_FREEZE_LOCK = 0xF5
    SECURITY_DISABLE_PASSWORD = 0xF6


# =============================================================================
# Security status bits in IDENTIFY DEVICE word 128 (ACS-3, Table 71)
# =============================================================================

IDENTIFY_WORD_SECURITY = 128


@dataclass
class ATASecurityStatus:
    """
    ATA Security Feature Set status decoded from IDENTIFY DEVICE word 128.

    Bit layout of word 128 (ACS-3, Section 7.12.7.69):
      bit 0   security_supported
      bit 1   security_enabled
      bit 2   security_locked
      bit 3   security_frozen
      bit 4   security_count_expired
      bit 5   enhanced_security_erase_supported
      bit 6   reserved
      bit 7   reserved
      bit 8   master_password_capability (0=high, 1=maximum)
      bits 9-14 reserved
      bit 15  security_level (0=high, 1=maximum) -- Seagate extension

    Sources:
      - ACS-3, Section 7.12.7.69: Word 128 (Security Status).
      - ATA/ATAPI-7 Volume 1, Section 6.17.1.
    """

    security_supported: bool = False
    security_enabled: bool = False
    security_locked: bool = False
    security_frozen: bool = False
    security_count_expired: bool = False
    enhanced_erase_supported: bool = False
    master_password_maximum: bool = False
    raw_word: int = 0

    @property
    def can_unlock(self) -> bool:
        return self.security_enabled and not self.security_frozen

    @property
    def can_freeze(self) -> bool:
        return not self.security_frozen

    @property
    def can_erase(self) -> bool:
        return self.security_enabled and not self.security_frozen

    @classmethod
    def from_identify(cls, identify_data: bytes) -> "ATASecurityStatus":
        """
        Parse IDENTIFY DEVICE response bytes and return security status.

        Args:
            identify_data: 512-byte IDENTIFY DEVICE response.

        Returns:
            ATASecurityStatus with all status bits populated.
        """
        if len(identify_data) < 512:
            return cls()
        word = struct.unpack_from("<H", identify_data, IDENTIFY_WORD_SECURITY * 2)[0]
        return cls(
            security_supported=bool(word & (1 << 0)),
            security_enabled=bool(word & (1 << 1)),
            security_locked=bool(word & (1 << 2)),
            security_frozen=bool(word & (1 << 3)),
            security_count_expired=bool(word & (1 << 4)),
            enhanced_erase_supported=bool(word & (1 << 5)),
            master_password_maximum=bool(word & (1 << 8)),
            raw_word=word,
        )

    def describe(self) -> str:
        """Return a one-line human-readable summary of the security state."""
        parts = []
        if not self.security_supported:
            return "Security feature set NOT supported"
        parts.append("supported")
        if self.security_enabled:
            parts.append("ENABLED")
        else:
            parts.append("disabled")
        if self.security_locked:
            parts.append("LOCKED")
        if self.security_frozen:
            parts.append("FROZEN")
        if self.security_count_expired:
            parts.append("count-expired")
        if self.enhanced_erase_supported:
            parts.append("enhanced-erase")
        pw = "MAXIMUM" if self.master_password_maximum else "HIGH"
        parts.append(f"master-pw={pw}")
        return ", ".join(parts)


# =============================================================================
# Password structure (32 bytes) used by SET PASSWORD / UNLOCK / DISABLE
# =============================================================================

_PASSWORD_SECTOR_SIZE = 512


def _build_password_sector(
    master: bool,
    password: bytes,
    identifier: int = 0,
    master_pw_rev: int = 0xFFFE,
) -> bytes:
    """
    Build the 512-byte password sector sent with SET PASSWORD / UNLOCK.

    Layout (ACS-3, Section 7.44.4 -- Control Word Sector):
      offset  0  2 bytes control word
                   bit 0: 0=user password, 1=master password
                   bits 15:8: master password revision (for SET PASSWORD)
      offset  2  32 bytes password (zero-padded)
      offset 34  2 bytes master password identifier (for SET PASSWORD)
      offset 36  476 bytes reserved

    Args:
        master: True if this is for the master password slot.
        password: Password bytes (max 32 bytes, zero-padded).
        identifier: Master password identifier (0 = not significant).
        master_pw_rev: Master password revision code for SET PASSWORD.

    Returns:
        Packed 512-byte sector.

    Sources:
      - ACS-3, Section 7.44.4: SECURITY SET PASSWORD control word.
    """
    control = 0x0001 if master else 0x0000
    pw_padded = password[:32].ljust(32, b"\x00")
    buf = bytearray(_PASSWORD_SECTOR_SIZE)
    struct.pack_into("<H", buf, 0, control)
    buf[2:34] = pw_padded
    struct.pack_into("<H", buf, 34, identifier)
    return bytes(buf)


# =============================================================================
# ATA Security Feature Set command builders
# =============================================================================


class ATASecurityAccess:
    """
    ATA Security Feature Set command builders and device interaction.

    The ATA Security Feature Set (ACS-3, Section 7.44) provides password-
    based access control for ATA drives.  The security state machine has
    five states:

      SEC0  Security disabled, frozen   (after power-on with no password)
      SEC1  Security disabled, not frozen
      SEC2  Security enabled, locked, frozen
      SEC3  Security enabled, locked, not frozen
      SEC4  Security enabled, unlocked, not frozen
      SEC5  Security enabled, frozen

    Key transitions:
      SET PASSWORD   SEC1 -> SEC4
      UNLOCK         SEC3 -> SEC4  (must supply correct password)
      FREEZE LOCK    SEC1 -> SEC0, SEC4 -> SEC5
      ERASE PREPARE  required before ERASE UNIT
      ERASE UNIT     SEC3/4 -> SEC1 (wipes user data on HDDs)
      DISABLE PASSWORD SEC4 -> SEC1

    Frozen bypass techniques:
      On some systems the drive enters the frozen state immediately at
      POST.  The standard bypass is to force a S3 (suspend-to-RAM) cycle:
        1. Remove the drive while the system is suspended.
        2. Re-insert and resume -- the drive returns from suspend unfrozen.
      This behaviour is documented in the BIOS / UEFI security guide from
      multiple vendors and exploited by tools such as hdparm.

    Sources:
      - ACS-3, Section 7.44: Security Feature Set.
      - ATA/ATAPI-7 Volume 1, Section 6.17.
      - hdparm man page (--security-* options).
      - "Self-Encrypting Drives" NIST SP 800-111 (2007), Section 4.1.
      - Boteanu & Bhargava BHEU 2015: frozen-state bypass via S3.
    """

    def __init__(self, device: ATADevice):
        self.dev = device

    def security_status(self, identify_data: bytes) -> ATASecurityStatus:
        """
        Parse security status from a pre-fetched IDENTIFY DEVICE buffer.

        Args:
            identify_data: 512-byte IDENTIFY DEVICE response.
        """
        return ATASecurityStatus.from_identify(identify_data)

    def set_password(
        self,
        password: bytes,
        master: bool = False,
        master_pw_rev: int = 0xFFFE,
    ) -> None:
        """
        Issue ATA SECURITY SET PASSWORD (0xF1).

        Sets the user or master password.  Transitions SEC1 -> SEC4.

        Args:
            password: Password bytes (max 32 bytes).
            master: True to set the master password instead of user.
            master_pw_rev: Master password revision code (0xFFFE = not set).

        Sources:
          - ACS-3, Section 7.44: SECURITY SET PASSWORD.
        """
        sector = _build_password_sector(
            master=master,
            password=password,
            master_pw_rev=master_pw_rev,
        )
        regs = _cmd_regs(ATASecurityCmd.SECURITY_SET_PASSWORD)
        self.dev.passthrough(regs, data_out=sector)

    def unlock(self, password: bytes, master: bool = False) -> None:
        """
        Issue ATA SECURITY UNLOCK (0xF2).

        Attempts to unlock the drive using the supplied password.
        Transitions SEC3 -> SEC4 on success.  After five consecutive
        failures the security count expires and the drive locks out
        further UNLOCK attempts until a power cycle.

        Args:
            password: Password bytes (max 32 bytes).
            master: True to use the master password slot.

        Sources:
          - ACS-3, Section 7.45: SECURITY UNLOCK.
        """
        sector = _build_password_sector(master=master, password=password)
        regs = _cmd_regs(ATASecurityCmd.SECURITY_UNLOCK)
        self.dev.passthrough(regs, data_out=sector)

    def erase_prepare(self) -> None:
        """
        Issue ATA SECURITY ERASE PREPARE (0xF3).

        Must be sent immediately before SECURITY ERASE UNIT.
        This two-step requirement prevents accidental erasure from
        a single errant command.

        Sources:
          - ACS-3, Section 7.46: SECURITY ERASE PREPARE.
        """
        regs = _cmd_regs(ATASecurityCmd.SECURITY_ERASE_PREPARE)
        self.dev.passthrough(regs, data_out=b"", data_in_size=0)

    def erase_unit(self, password: bytes, master: bool = False, enhanced: bool = False) -> None:
        """
        Issue ATA SECURITY ERASE UNIT (0xF4).

        Erases all user data on the drive and resets the password.
        Must be preceded by SECURITY ERASE PREPARE.

        For SEDs, the drive re-generates the internal encryption key
        (cryptographic erase) rather than overwriting every sector.
        For HDDs without SED, a full sector-by-sector overwrite is
        performed; enhanced erase uses vendor-specific patterns.

        Args:
            password: Password bytes.
            master: True to use the master password.
            enhanced: True to request enhanced security erase.

        Sources:
          - ACS-3, Section 7.47: SECURITY ERASE UNIT.
        """
        sector = bytearray(_build_password_sector(master=master, password=password))
        if enhanced:
            sector[0] |= 0x02
        regs = _cmd_regs(ATASecurityCmd.SECURITY_ERASE_UNIT)
        self.dev.passthrough(regs, data_out=bytes(sector))

    def freeze_lock(self) -> None:
        """
        Issue ATA SECURITY FREEZE LOCK (0xF5).

        Transitions the drive to the frozen state, preventing any
        further password-related commands until the next power cycle.
        Most systems issue this command at POST to prevent cold-boot
        attacks.

        Sources:
          - ACS-3, Section 7.48: SECURITY FREEZE LOCK.
        """
        regs = _cmd_regs(ATASecurityCmd.SECURITY_FREEZE_LOCK)
        self.dev.passthrough(regs, data_out=b"", data_in_size=0)

    def disable_password(self, password: bytes, master: bool = False) -> None:
        """
        Issue ATA SECURITY DISABLE PASSWORD (0xF6).

        Disables the security feature set, returning the drive to SEC1.
        Requires the drive to be in SEC4 (unlocked).

        Args:
            password: Current user or master password bytes.
            master: True to use the master password.

        Sources:
          - ACS-3, Section 7.49: SECURITY DISABLE PASSWORD.
        """
        sector = _build_password_sector(master=master, password=password)
        regs = _cmd_regs(ATASecurityCmd.SECURITY_DISABLE_PASSWORD)
        self.dev.passthrough(regs, data_out=sector)


def _cmd_regs(cmd: ATASecurityCmd) -> dict:
    return {
        "features": 0,
        "count": 1,
        "lba_lo": 0,
        "cyl_lo": 0,
        "cyl_hi": 0,
        "dev": 0xA0,
        "cmd": int(cmd),
    }


# =============================================================================
# Frozen-state bypass analysis
# =============================================================================


class ATAFrozenBypass:
    """
    Analysis and guidance for ATA SECURITY FREEZE LOCK bypass techniques.

    Modern BIOS/UEFI firmware issues SECURITY FREEZE LOCK at POST to
    prevent password manipulation after boot.  Several bypass techniques
    are documented:

    S3 Suspend/Resume (hot-plug)
    ----------------------------
    Some systems do not re-issue FREEZE LOCK after S3 resume.
    Procedure:
      1. Boot the target system and suspend to RAM (S3).
      2. Physically remove the drive while the system is suspended.
      3. Re-insert the drive.
      4. Resume the system -- the drive rejoins the bus in SEC4 (unfrozen).
    Applicability: BIOS systems that lack FREEZE LOCK in the S3 resume path.

    USB Bridge Detour
    -----------------
    Attaching the drive through a USB-to-SATA bridge (e.g. JMicron JMS578)
    may reset the FREEZE state because the bridge's own power-on sequence
    does not forward the FREEZE command from the host.

    Direct Power Cycle (with interposer)
    --------------------------------------
    An SATA interposer card can selectively remove power from the drive
    while keeping the data lines connected, simulating a power cycle.
    After the drive reinitialises the host may be able to issue password
    commands before the OS re-issues FREEZE LOCK.

    Vendor-Specific Unlock
    -----------------------
    Some drives accept a vendor-specific SMART command that clears the
    frozen bit.  This is not documented in the ACS spec and is drive-
    specific (observed on certain WD and Seagate models).

    Sources:
      - Boteanu & Bhargava, "Bypassing Self-Encrypting Drives" (BHEU 2015).
      - NIST SP 800-111, Section 4.1 (2007).
      - hdparm documentation, "--security-unlock" notes.
      - Jon "JCS" Solworth, "ATA Security & SEDs" (presentation, 2012).
    """

    @staticmethod
    def analyse(status: ATASecurityStatus) -> dict:
        """
        Analyse the security status and return applicable bypass options.

        Args:
            status: ATASecurityStatus from ATASecurityAccess.security_status().

        Returns:
            Dict with keys:
              state_description  -- human-readable state summary
              frozen             -- bool
              locked             -- bool
              bypass_options     -- list of applicable technique names
              recommendations    -- list of actionable steps
        """
        options: list[str] = []
        recommendations: list[str] = []

        if not status.security_supported:
            return {
                "state_description": "Security feature set not supported",
                "frozen": False,
                "locked": False,
                "bypass_options": [],
                "recommendations": [],
            }

        if status.security_frozen:
            options += ["s3_suspend_resume", "usb_bridge_detour", "power_cycle_interposer"]
            recommendations += [
                "Attempt S3 suspend/resume with drive hot-unplug during suspend",
                "Attach drive via USB-to-SATA bridge without issuing FREEZE LOCK",
                "Use SATA interposer to cut drive power, then re-apply before OS resumes",
            ]

        if status.security_locked and not status.security_frozen:
            options.append("brute_force_unlock")
            recommendations.append(
                "Issue SECURITY UNLOCK with candidate passwords "
                "(note: 5-attempt lockout per power cycle)"
            )

        if not status.security_enabled:
            recommendations.append(
                "Drive has no password set; use SET PASSWORD to enable security"
            )

        return {
            "state_description": status.describe(),
            "frozen": status.security_frozen,
            "locked": status.security_locked,
            "bypass_options": options,
            "recommendations": recommendations,
        }
