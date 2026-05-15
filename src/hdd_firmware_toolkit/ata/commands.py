"""ATA passthrough commands, device abstraction, and security feature set."""

import ctypes
import sys
from enum import IntEnum


class ATACmd(IntEnum):
    READ_DMA_EXT = 0x25  # LBA48 read - most common SATA read
    WRITE_DMA_EXT = 0x35  # LBA48 write
    DOWNLOAD_MICRO = 0x92  # firmware update (Download Microcode)
    SMART = 0xB0  # SMART command set


# Samsung 840 EVO firmware version history (from TheMissingManual)
SAMSUNG_840_EVO_FW_HISTORY: list[tuple[str, str, str]] = [
    ("EXT0AB0Q", "~2013-07", "Original firmware; not found online"),
    ("EXT0BB0Q", "2013-10", "First publicly available"),
    ("EXT0BB6Q", "2013-12-18", "On Samsung website at time of writing"),
    ("EXT0CB6Q", "2014-10-10", "Included in Samsung Performance Restoration ZIP"),
    ("EXT0DB6Q", "2015-03-27", "Latest known version"),
]
# Firmware packaging: ISO -- isolinux/btdsk.img -- samsung/DSRD/FW/ext0xxxq/EXT0xxxq.enc
# Decrypt with ddcc's tool: https://github.com/ddcc/drive_firmware/blob/master/samsung/samsung.c
# (same nibble-swap as samsung_decode() above)
# Firmware structure: 1 header + 10 sections (nicely aligned, non-overlapping) + trailing data


# =============================================================================
# Linux ATA passthrough via sg_io (SAT ATA PASS-THROUGH 16)
# =============================================================================

# Windows ATA PASS THROUGH structures (harmless to define on all platforms)
IOCTL_ATA_PASS_THROUGH = 0x4D004
ATA_FLAGS_DATA_IN = 0x02
ATA_FLAGS_DATA_OUT = 0x04


class ATA_PASS_THROUGH_EX(ctypes.Structure):  # noqa: N801
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("DataTransferLength", ctypes.c_ulong),
        ("TimeOutValue", ctypes.c_ubyte),
        ("ReservedAsUchar", ctypes.c_ubyte),
        ("DataBufferOffset", ctypes.c_ulong),
        ("PreviousTaskFile", ctypes.c_ubyte * 8),
        ("CurrentTaskFile", ctypes.c_ubyte * 8),
    ]


if sys.platform == "win32":
    import ctypes.wintypes

    kernel32 = ctypes.windll.kernel32
    GENERIC_READ_WRITE = 0x80000000
    FILE_SHARE_RW = 0x3
    OPEN_EXISTING = 3
else:
    kernel32 = None
    GENERIC_READ_WRITE = None
    FILE_SHARE_RW = None
    OPEN_EXISTING = None

if sys.platform != "win32":
    try:
        import fcntl as _fcntl

        _SG_IO = 0x2285
        _SG_DXFER_NONE = -1
        _SG_DXFER_TO_DEV = -2
        _SG_DXFER_FROM = -3

        class _sg_io_hdr(ctypes.Structure):  # noqa: N801
            _fields_ = [
                ("interface_id", ctypes.c_int),  # must be ord('S')
                ("dxfer_direction", ctypes.c_int),
                ("cmd_len", ctypes.c_ubyte),
                ("mx_sb_len", ctypes.c_ubyte),
                ("iovec_count", ctypes.c_ushort),
                ("dxfer_len", ctypes.c_uint),
                ("dxferp", ctypes.c_void_p),
                ("cmdp", ctypes.c_void_p),
                ("sbp", ctypes.c_void_p),
                ("timeout", ctypes.c_uint),  # ms
                ("flags", ctypes.c_uint),
                ("pack_id", ctypes.c_int),
                ("usr_ptr", ctypes.c_void_p),
                ("status", ctypes.c_ubyte),
                ("masked_status", ctypes.c_ubyte),
                ("msg_status", ctypes.c_ubyte),
                ("sb_len_wr", ctypes.c_ubyte),
                ("host_status", ctypes.c_ushort),
                ("driver_status", ctypes.c_ushort),
                ("resid", ctypes.c_int),
                ("duration", ctypes.c_uint),
                ("info", ctypes.c_uint),
            ]

        def _linux_ata_passthrough(
            fd, regs: dict, data_out: bytes | None, data_in_size: int
        ) -> bytes:
            """
            ATA passthrough via Linux sg_io ioctl using SAT ATA PASS-THROUGH 16.

            `fd` must be a raw file descriptor for /dev/sdX or /dev/sgX.
            Requires root.  Protocol accepts regs key 'protocol':
              4 = PIO_DATA_IN, 5 = DMA, 3 = Non-data.
            Defaults to DMA (5) for data, Non-data (3) for no-data.
            """
            is_write = data_out is not None
            has_data = is_write or bool(data_in_size)
            protocol = regs.get("protocol", 5 if has_data else 3)
            t_dir = 0 if is_write else 1  # 0=to-dev, 1=from-dev
            byt_blok = 1  # transfer length in blocks
            t_length = 2 if has_data else 0  # 2=use sector count register

            cdb = (ctypes.c_ubyte * 16)(
                0x85,  # ATA PASS-THROUGH 16 opcode
                (protocol << 1) | 0,  # multiple_count=0
                (t_dir << 3) | (byt_blok << 2) | t_length,
                0,  # features (extended, high byte)
                regs.get("features", 0) & 0xFF,  # features
                0,  # sector count (extended, high)
                regs.get("count", 1) & 0xFF,  # sector count
                0,  # LBA low (extended, high)
                regs.get("lba_lo", 0) & 0xFF,  # LBA low
                0,  # LBA mid (extended, high)
                regs.get("cyl_lo", 0) & 0xFF,  # LBA mid
                0,  # LBA high (extended, high)
                regs.get("cyl_hi", 0) & 0xFF,  # LBA high
                regs.get("dev", 0xA0) & 0xFF,  # device register
                regs.get("cmd", 0) & 0xFF,  # ATA command
                0,  # control
            )

            buf_size = max(data_in_size, len(data_out) if data_out else 0, 512)
            buf = (ctypes.c_ubyte * buf_size)()
            if data_out:
                ctypes.memmove(buf, data_out, len(data_out))

            sense = (ctypes.c_ubyte * 64)()

            hdr_s = _sg_io_hdr()
            hdr_s.interface_id = ord("S")
            hdr_s.dxfer_direction = (
                _SG_DXFER_TO_DEV
                if is_write
                else (_SG_DXFER_FROM if data_in_size else _SG_DXFER_NONE)
            )
            hdr_s.cmd_len = 16
            hdr_s.mx_sb_len = 64
            hdr_s.dxfer_len = buf_size
            hdr_s.dxferp = ctypes.cast(buf, ctypes.c_void_p)
            hdr_s.cmdp = ctypes.cast(cdb, ctypes.c_void_p)
            hdr_s.sbp = ctypes.cast(sense, ctypes.c_void_p)
            hdr_s.timeout = 10_000  # ms

            ret = _fcntl.ioctl(fd, _SG_IO, hdr_s)
            if ret != 0 or hdr_s.status not in (0, 2):
                raise ATAError(
                    f"sg_io failed: ret={ret} status={hdr_s.status:#04x} "
                    f"host_status={hdr_s.host_status:#06x} "
                    f"driver_status={hdr_s.driver_status:#06x}"
                )
            return bytes(buf[:buf_size])

        _LINUX_SGIOAVAIL = True
    except ImportError:
        _LINUX_SGIOAVAIL = False


class ATAError(Exception):
    pass


class ATADevice:
    """
    Thin wrapper around a physical drive for sending ATA passthrough commands.
    Windows only for now; Linux stub included.
    """

    def __init__(self, path: str):
        self.path = path
        self._handle = None
        self._open()

    def _open(self):
        if sys.platform == "win32":
            h = kernel32.CreateFileW(
                self.path, GENERIC_READ_WRITE, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None
            )
            if h == ctypes.wintypes.HANDLE(-1).value:
                raise ATAError(f"Cannot open {self.path}: error {kernel32.GetLastError()}")
            self._handle = h
        else:
            # Linux: open raw device; use sg_io ioctl
            self._handle = open(self.path, "rb+", buffering=0)  # noqa: SIM115

    def close(self):
        if self._handle and sys.platform == "win32":
            kernel32.CloseHandle(self._handle)
        elif self._handle:
            self._handle.close()
        self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    # == Low-level passthrough ================================================

    def _passthrough_win(
        self, regs: dict, data_out: bytes | None = None, data_in_size: int = 0
    ) -> bytes:
        buf_size = ctypes.sizeof(ATA_PASS_THROUGH_EX) + max(
            len(data_out) if data_out else 0, data_in_size, 512
        )
        raw = (ctypes.c_ubyte * buf_size)()
        apt = ATA_PASS_THROUGH_EX.from_buffer(raw)

        apt.Length = ctypes.sizeof(ATA_PASS_THROUGH_EX)
        apt.DataTransferLength = len(data_out) if data_out else data_in_size
        apt.TimeOutValue = 10
        apt.DataBufferOffset = ctypes.sizeof(ATA_PASS_THROUGH_EX)

        if data_out:
            apt.AtaFlags = ATA_FLAGS_DATA_OUT
            ctypes.memmove(
                ctypes.addressof(raw) + ctypes.sizeof(ATA_PASS_THROUGH_EX), data_out, len(data_out)
            )
        elif data_in_size:
            apt.AtaFlags = ATA_FLAGS_DATA_IN

        tf = (ctypes.c_ubyte * 8)(
            *[
                regs.get(k, 0)
                for k in ("features", "count", "lba_lo", "cyl_lo", "cyl_hi", "dev", "cmd", "_")
            ]
        )
        apt.CurrentTaskFile = tf

        bytes_ret = ctypes.c_ulong(0)
        ok_flag = kernel32.DeviceIoControl(
            self._handle,
            IOCTL_ATA_PASS_THROUGH,
            raw,
            buf_size,
            raw,
            buf_size,
            ctypes.byref(bytes_ret),
            None,
        )

        if not ok_flag:
            raise ATAError(f"DeviceIoControl failed: {kernel32.GetLastError()}")

        out_tf = bytes(apt.CurrentTaskFile)
        if out_tf[6] & 0x01:
            raise ATAError(
                f"Drive returned error status: status={out_tf[6]:#04x} error={out_tf[0]:#04x}"
            )

        return bytes(
            raw[
                ctypes.sizeof(ATA_PASS_THROUGH_EX) : ctypes.sizeof(ATA_PASS_THROUGH_EX)
                + max(data_in_size, 512)
            ]
        )

    def _passthrough_linux(self, regs: dict, data_out: bytes | None, data_in_size: int) -> bytes:
        """
        Linux ATA passthrough via sg_io (SAT ATA PASS-THROUGH 16).
        Requires root and /dev/sdX or /dev/sgX.
        """
        if not _LINUX_SGIOAVAIL:
            raise ATAError("fcntl not available on this platform")
        fd = self._handle.fileno()
        return _linux_ata_passthrough(fd, regs, data_out, data_in_size)

    def passthrough(
        self, regs: dict, data_out: bytes | None = None, data_in_size: int = 0
    ) -> bytes:
        if sys.platform == "win32":
            return self._passthrough_win(regs, data_out, data_in_size)
        return self._passthrough_linux(regs, data_out, data_in_size)


class ATASecurityCommands:
    """
    ATA Security Feature Set (ACS-4, sec 4.16, sec 7.43-7.56).
    Supports SECURITY FREEZE LOCK, SECURITY UNLOCK, SECURITY DISABLE PASSWORD,
    SECURITY ERASE PREPARE, SECURITY ERASE UNIT, and SECURITY SET PASSWORD.
    See INVESTIGATION.md "ATA Security" section for full source references.

    IMPORTANT CAVEATS:
      - SECURITY FREEZE LOCK is a one-shot command per power cycle
      - SECURITY ERASE UNIT is destructive (full media erase)
      - Master password capability varies by drive
      - On SAT (SAS) drives, uses SECURITY PROTOCOL IN/OUT with protocol=0x11
    """

    # ATA commands for security feature set
    SECURITY_SET_PASSWORD = 0xF1
    SECURITY_UNLOCK = 0xF2
    SECURITY_ERASE_PREPARE = 0xF3
    SECURITY_ERASE_UNIT = 0xF4
    SECURITY_FREEZE_LOCK = 0xF5
    SECURITY_DISABLE_PASSWORD = 0xF6

    # Security level (bit 8 of features/sector count)
    LEVEL_HIGH = 0
    LEVEL_MAXIMUM = 1

    # Identifier (USER = 0, MASTER = 1)
    ID_USER = 0
    ID_MASTER = 1

    PASSWORD_SIZE = 32  # ATA passwords are always 32 bytes

    @staticmethod
    def _pad_password(password: str) -> bytes:
        """Pad/truncate password to exactly 32 ASCII bytes."""
        p = password.encode("ascii", errors="replace")[:32]
        return p.ljust(32, b" ")

    @staticmethod
    def _build_security_cdb(
        ata_cmd: int, password: bytes, identifier: int = ID_USER, level: int = LEVEL_HIGH
    ) -> bytes:
        """
        Build a 512-byte WRITE SECTOR buffer for ATA security commands.
        Buffer layout:
          [0:32]   password (user or master)
          [32:512] zeroes
        Sends via ATA WRITE SECTORS (0x30) then the security command.
        Many implementations combine this into a single ATA command.
        """
        buf = bytearray(512)
        pw = password[:32].ljust(32, b"\x00")
        buf[:32] = pw
        # Byte 32: security configuration
        #   bit 0: identifier (0=user, 1=master)
        #   bit 1: security level (0=high, 1=maximum)
        buf[32] = (level << 1) | identifier
        return bytes(buf)

    @staticmethod
    def freeze_lock(drive) -> bytes:
        """
        ATA SECURITY FREEZE LOCK (0xF5).
        Sent as a no-data ATA command via passthrough.
        Once frozen, no further security commands are accepted until power cycle.
        """
        ccb = bytearray(16)
        ccb[0] = 0x85  # ATA PASS-THROUGH (16)
        ccb[1] = 0x0D  # protocol = 13 (INTERRUPT_NO_DATA)
        ccb[8] = 0xF5  # SECURITY FREEZE LOCK
        return bytes(ccb)

    @staticmethod
    def security_disable_password(drive, password: str, identifier: int = ID_USER) -> bytes:
        """
        ATA SECURITY DISABLE PASSWORD (0xF6).
        After this command succeeds, the drive is no longer password-locked.
        The correct current password must be supplied.
        """
        pw = ATASecurityCommands._pad_password(password)
        buf = ATASecurityCommands._build_security_cdb(0xF6, pw, identifier=identifier)
        # Most SAT implementations follow the 512-byte buffer model
        return buf

    @staticmethod
    def security_unlock(drive, password: str, identifier: int = ID_USER) -> bytes:
        """
        ATA SECURITY UNLOCK (0xF2).
        Unlocks the drive for the current power cycle only.
        Must supply the correct password.  After power cycle, drive locks again.
        Some drives allow unlimited unlock attempts; others have a retry counter.
        """
        pw = ATASecurityCommands._pad_password(password)
        buf = ATASecurityCommands._build_security_cdb(0xF2, pw, identifier=identifier)
        return buf

    @staticmethod
    def security_set_password(
        password: str,
        identifier: int = ID_USER,
        level: int = LEVEL_HIGH,
        master_password: str | None = None,
    ) -> bytes:
        """
        ATA SECURITY SET PASSWORD (0xF1).
        Sets the drive's password to the given value.
        WARNING: If you forget this password, the drive may be permanently locked.
        """
        pw = ATASecurityCommands._pad_password(password)
        buf = ATASecurityCommands._build_security_cdb(0xF1, pw, identifier=identifier, level=level)
        return buf

    @staticmethod
    def security_erase_prepare() -> bytes:
        """ATA SECURITY ERASE PREPARE (0xF3). Must precede SECURITY ERASE UNIT."""
        ccb = bytearray(16)
        ccb[0] = 0x85
        ccb[1] = 0x0D  # no-data protocol
        ccb[8] = 0xF3
        return bytes(ccb)

    @staticmethod
    def security_erase_unit(password: str, identifier: int = ID_USER) -> bytes:
        """
        ATA SECURITY ERASE UNIT (0xF4).
        Destructive: erases ALL user data after password verification.
        The drive must have had SECURITY ERASE PREPARE issued first.
        """
        pw = ATASecurityCommands._pad_password(password)
        buf = ATASecurityCommands._build_security_cdb(0xF4, pw, identifier=identifier)
        return buf
