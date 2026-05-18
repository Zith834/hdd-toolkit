"""Seagate F3 UART terminal command builder and session model."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar


class F3Level(IntEnum):
    """Seagate F3 UART terminal prompt levels.

    The F3 terminal presents different prompt levels depending on the
    current drive state and which access mode is active.

    Sources:
      - INVESTIGATION.md -- "HDD Serial Commander -- Seagate F3 UART terminal"
      - forum.hddguru.com -- "Seagate F3 terminal command reference"
      - MalwareTech blog -- "Hard Disk Firmware Hacking" (2015):
          Level 1 is the normal user-accessible mode; Level T is factory.
    """

    LEVEL_0 = 0
    LEVEL_1 = 1
    LEVEL_T = ord("T")


# F3 terminal command strings (ASCII, sent over UART, terminated by CR LF)
F3_SPIN_UP = "U"
F3_SPIN_DOWN = "Z"
F3_SOFT_RESET = "R"
F3_PRINT_IDENTITY = "Q"
F3_PRINT_VERSION = "V"
F3_PRINT_P_LIST = "P"
F3_PRINT_G_LIST = "G"
F3_SELF_TEST = "T"
F3_TOGGLE_SATA = "/1"
F3_ENTER_TERMINAL = "/T"
F3_CLEAR_SMART = "B"
F3_CLEAR_G_LIST = "C6"

# Escape sequence to enter level 1 from level 0
F3_CTRL_Z = b"\x1a"

# Default baud rate for F3 terminal access
F3_BAUD_LEGACY = 38400
F3_BAUD_MODERN = 115200


@dataclass
class F3SAReadCmd:
    """Decoded Seagate F3 SA read command string.

    The `i` command reads or writes SA modules directly.  The format is:
      i{type},{track},{module}[,{offset}[,{length}[,{flags}]]]

    type 4 = SA read (retrieve module data)
    type 5 = SA write (inject module data)

    Sources:
      - forum.hddguru.com -- "Seagate F3 i-command reference (i4,i5)"
      - INVESTIGATION.md -- "HDD Serial Commander": i4,1,22 reads mod 22 on track 1
    """

    cmd_type: int
    track: int
    module_id: int
    offset: int = 0
    length: int = 0
    flags: int = 0

    def encode(self) -> str:
        """Build the F3 terminal command string for this SA operation."""
        base = f"i{self.cmd_type},{self.track},{self.module_id}"
        if self.offset or self.length or self.flags:
            base += f",{self.offset},{self.length},{self.flags}"
        return base


@dataclass
class F3IdentityInfo:
    """Parsed drive identity returned by the F3 `Q` command.

    The Q command prints ASCII lines such as:
      Model: ST4000DM004-2CV104
      S/N:   WS12ABCD
      FW:    0001
      Cyl:   775156  Hds: 2  Spt: 63

    Sources:
      - forum.hddguru.com -- "Seagate F3 Q command output format"
    """

    model: str = ""
    serial: str = ""
    firmware: str = ""
    cylinders: int = 0
    heads: int = 0
    sectors_per_track: int = 0
    raw_lines: list[str] = field(default_factory=list)


@dataclass
class F3TerminalResponse:
    """Response from a single F3 terminal command.

    Sources:
      - forum.hddguru.com -- "Seagate F3 terminal response format"
    """

    command: str
    raw: str
    success: bool
    error_code: int = 0


class SeagateF3Terminal:
    """Seagate F3 UART terminal command builder and response parser.

    Seagate F3-architecture drives (Barracuda, IronWolf, Exos, Constellation
    families manufactured since 2009) expose an RS-232 TTL diagnostic UART on
    the PCB.  Connecting a 3.3 V USB-serial adapter to the PCB test points
    (commonly labelled T1/T2/T3 or RX/TX/GND) gives access to a shell-like
    terminal with factory commands for:
      - Head management (spin, select, disable)
      - Defect list access (P-list / G-list read and clear)
      - Service Area module read/write via the ``i`` command family
      - Drive identity interrogation
      - Diagnostic self-test initiation

    This class does NOT require a real serial connection; it builds the correct
    ASCII command strings and parses ASCII responses so they can be sent by the
    caller's serial transport layer (pyserial, subprocess, TCP, etc.).

    Typical usage pattern:
      1. Connect USB-serial at F3_BAUD_LEGACY (38400 baud, 8N1).
      2. Send ``F3_CTRL_Z`` to enter Level 1 (F3 1> prompt).
      3. Build commands with the class methods and send them.
      4. Parse responses with ``parse_response`` or ``parse_identity``.

    Sources:
      - INVESTIGATION.md -- "HDD Serial Commander -- Seagate F3 UART terminal":
          Full command reference including spin, SA access, P/G-list ops.
      - forum.hddguru.com -- "Seagate F3 terminal command reference"
      - MalwareTech blog -- "Hard Disk Firmware Hacking" (2015):
          F3 level 1 gives direct SA module write access useful for FW injection.
    """

    PROMPT_LEVEL_1 = "F3 1>"
    PROMPT_LEVEL_T = "F3 T>"
    PROMPT_LEVEL_0 = "LED:000000CC FAddr:0025B488"

    @staticmethod
    def enter_level1() -> bytes:
        """Return the byte sequence to enter F3 Level 1 from power-on state."""
        return F3_CTRL_Z

    @staticmethod
    def spin_up() -> str:
        """Build the spin-up command string."""
        return F3_SPIN_UP

    @staticmethod
    def spin_down() -> str:
        """Build the spin-down command string."""
        return F3_SPIN_DOWN

    @staticmethod
    def soft_reset() -> str:
        """Build the soft-reset command string."""
        return F3_SOFT_RESET

    @staticmethod
    def print_identity() -> str:
        """Build the identity query command string (Q)."""
        return F3_PRINT_IDENTITY

    @staticmethod
    def print_p_list() -> str:
        """Build the P-list print command string."""
        return F3_PRINT_P_LIST

    @staticmethod
    def print_g_list() -> str:
        """Build the G-list print command string."""
        return F3_PRINT_G_LIST

    @staticmethod
    def clear_g_list() -> str:
        """Build the G-list clear command string.

        CAUTION: This removes all grown defect entries.  Only use during
        controlled data recovery when the G-list is causing read failures.
        """
        return F3_CLEAR_G_LIST

    @staticmethod
    def set_active_heads(head_count: int, head_mask: int = 0xFF) -> str:
        """Build the head-select command string.

        The N command enables selective head reads for data recovery when
        one platter surface has failed.  head_mask is a bitmask of which
        physical heads to keep enabled (0xFF = all).

        Args:
            head_count: number of heads to activate.
            head_mask:  bitmask of head IDs to enable.

        Returns:
            F3 terminal command string, e.g. 'N2,3' for 2 heads, mask=3.
        """
        return f"N{head_count & 0xFF},{head_mask & 0xFF}"

    @staticmethod
    def build_sa_read(module_id: int, track: int = 1, sa_type: int = 4) -> F3SAReadCmd:
        """Build an F3 SA read command descriptor.

        Args:
            module_id: SA module number to read (0x00-0xFF typical range).
            track:     SA track number (default 1, SA track 0 = reserved).
            sa_type:   Command type (4=read, 5=write).

        Returns:
            F3SAReadCmd with ``.encode()`` returning the terminal string.
        """
        return F3SAReadCmd(cmd_type=sa_type, track=track, module_id=module_id)

    @staticmethod
    def build_sa_write(module_id: int, track: int = 1) -> F3SAReadCmd:
        """Build an F3 SA write command descriptor (type 5)."""
        return F3SAReadCmd(cmd_type=5, track=track, module_id=module_id)

    @staticmethod
    def parse_response(raw: str, command: str = "") -> F3TerminalResponse:
        """Parse a raw F3 terminal response string.

        Seagate F3 error responses begin with 'ERR' followed by a hex error
        code.  A successful response returns any printed data and ends with
        the prompt prefix.

        Args:
            raw:     Raw ASCII response string from the terminal.
            command: The command that produced this response (for context).

        Returns:
            F3TerminalResponse with success/error info.
        """
        raw_stripped = raw.strip()
        if raw_stripped.startswith("ERR"):
            parts = raw_stripped.split()
            try:
                code = int(parts[1], 16) if len(parts) > 1 else -1
            except ValueError:
                code = -1
            return F3TerminalResponse(command=command, raw=raw, success=False, error_code=code)
        return F3TerminalResponse(command=command, raw=raw, success=True)

    @staticmethod
    def parse_identity(raw: str) -> F3IdentityInfo:
        """Parse F3 `Q` command output into an F3IdentityInfo dataclass.

        Example output:
          Model: ST4000DM004-2CV104
          S/N:   WS12ABCDEF01
          FW:    CC54
          Cyl:   775156  Hds: 2  Spt: 63

        Args:
            raw: Multi-line ASCII response from the Q command.

        Returns:
            F3IdentityInfo with all parsed fields.
        """
        info = F3IdentityInfo()
        lines = [line.strip() for line in raw.splitlines() if line.strip()]
        info.raw_lines = lines
        for line in lines:
            lower = line.lower()
            if lower.startswith("model:"):
                info.model = line.split(":", 1)[1].strip()
            elif lower.startswith("s/n:") or lower.startswith("serial"):
                info.serial = line.split(":", 1)[1].strip()
            elif lower.startswith("fw:") or lower.startswith("firmware"):
                info.firmware = line.split(":", 1)[1].strip()
            elif "cyl" in lower:
                for token in line.replace(",", " ").split():
                    if token.isdigit():
                        if not info.cylinders:
                            info.cylinders = int(token)
                        elif not info.heads:
                            info.heads = int(token)
                        elif not info.sectors_per_track:
                            info.sectors_per_track = int(token)
        return info

    @staticmethod
    def build_format_sa(track: int = 0, surface: int = 2, step: int = 2) -> str:
        """Build the SA format command string.

        The ``m`` command reformats a service-area track.  This is a destructive
        operation used in data recovery when the SA has been corrupted.

        CAUTION: Formatting the SA destroys all calibration data, firmware
        modules, and defect lists stored on the selected track.  The drive
        will be inoperable until the SA is reprogrammed.

        Args:
            track:   SA track to format (0 = primary SA track).
            surface: Platter surface (0-based, 2 = default inner surface).
            step:    Step pattern (2 = factory default).

        Returns:
            F3 terminal command string.

        Sources:
          - forum.hddguru.com -- "m command reference for Seagate F3"
        """
        return f"m0,{track},{surface},{step},0,0,0,0"

    @staticmethod
    def build_toggle_sata() -> str:
        """Build the SATA interface toggle command (/1).

        Toggling SATA can help when the host has frozen the ATA security
        state; cycling the interface resets the freeze latch on some drives.

        Sources:
          - forum.hddguru.com -- "/1 command: SATA toggle for security freeze bypass"
        """
        return F3_TOGGLE_SATA

    @staticmethod
    def build_enter_terminal_mode() -> str:
        """Build the command to enter terminal/factory mode (F3 T>)."""
        return F3_ENTER_TERMINAL


class SeagateF3ROMMap:
    """Known Seagate F3 SA module layout for common drive families.

    SA module numbering for Barracuda (ST3000DM001/ST4000DM004 era):
      Module  0x03 = ROM Resident 0 (always loaded at spin-up)
      Module  0x0B = ROM Resident 1
      Module  0x1D = Physical Overlay 0
      Module  0x1E = Physical Overlay 1
      Module  0x1F = Physical Overlay 2
      Module  0x34 = Packed CONGEN XML (drive personality definition)
      Module  0x50 = Defect Management (P-list header)
      Module  0x51 = G-list (grown defect log)

    Sources:
      - INVESTIGATION.md -- "Analysis of Seagate LOD firmware image"
      - forum.hddguru.com -- "Seagate F3 SA module list (Barracuda 7200.14)"
    """

    BARRACUDA_7200_14: ClassVar[dict[int, str]] = {
        0x03: "ROM_RESIDENT_0",
        0x0B: "ROM_RESIDENT_1",
        0x1D: "PHYSICAL_OVERLAY_0",
        0x1E: "PHYSICAL_OVERLAY_1",
        0x1F: "PHYSICAL_OVERLAY_2",
        0x34: "CONGEN_XML",
        0x50: "P_LIST_HEADER",
        0x51: "G_LIST",
    }

    @staticmethod
    def describe(module_id: int) -> str:
        """Return a human-readable name for a Barracuda 7200.14 SA module ID."""
        return SeagateF3ROMMap.BARRACUDA_7200_14.get(module_id, f"UNKNOWN_0x{module_id:02X}")


def build_sa_sector_descriptor(module_id: int, op: int = 0x01, length: int = 0) -> bytes:
    """Build a 512-byte SA command descriptor for direct SMART log injection.

    This descriptor is written to SMART log 0xE0 (SCT command transport)
    when issuing F3 SA commands via ATA -- as distinct from the UART
    terminal ``i`` command, which is used when physically connected.

    Args:
        module_id: SA module ID (0x00-0xFF).
        op:        0x01=read, 0x02=write.
        length:    Module length in sectors (0=auto).

    Returns:
        512-byte descriptor ready for SMART WRITE LOG.
    """
    buf = bytearray(512)
    buf[0] = op & 0xFF
    buf[1] = module_id & 0xFF
    struct.pack_into("<H", buf, 2, length & 0xFFFF)
    return bytes(buf)
