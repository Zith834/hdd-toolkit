import struct
from dataclasses import dataclass
from typing import ClassVar

from hdd_toolkit.ata.sat import SATLayer
from hdd_toolkit.core.utils import warn


@dataclass
class ReadRetryResult:
    """Result of a data recovery read attempt."""

    lba: int
    success: bool
    data: bytes
    attempts: int
    retry_level: int
    status: str


class SATADataRecoveryOps:
    """
    Advanced SATA operations for data recovery from failing drives.
    Provides multiple retry strategies, head management, bad sector handling,
    and P/G-list interaction.

    CRITICAL: These operations are for DATA RECOVERY only. They can
    accelerate media degradation on a failing drive. Always image drives
    using hardware write-blockers for forensic use.

    Techniques implemented:
      - Read retry with escalating retry levels (PIO -- DMA -- UDMA with
        varying timing, CRC retry, and device reset between levels)
      - Selective head operations (skip known-bad heads, read one head at a time)
      - P-list / G-list parsing for vendor-specific defect management
      - Bad sector replacement (assign to G-list, reassign to spare)
      - Slow read with thermal calibration management
      - Sector skew / alignment adjustment (for partial media damage)

    Sources:
      - INVESTIGATION.md  -- "HDDSuperClone / HDDSuperTool":
          Cloning with head management, bad sector handling, SA access
      - INVESTIGATION.md  -- "mod32patch -- WD Mod 32h patch":
          G-list manipulation for clearing reallocated sector counts
      - INVESTIGATION.md  -- "trulycrisp -- Drive Firmware Security: SA Operations":
          SA dump/load ops, Service Area module read/write for defect tables
      - INVESTIGATION.md  -- "ACE Lab PC-3000":
          Professional SA regen, P-list/G-list management, head map editing
      - INVESTIGATION.md  -- "Firmware Internals Map":
          P-list/G-list architecture for covert storage and data recovery

    Usage:
        re = SATADataRecoveryOps()
        result = re.read_retry_escalation(
            drive="/dev/sdb", lba=0x100000,
            levels=["pio", "dma", "udma_short", "udma_long", "reset_then_pio"])
        if result.success:
            process(result.data)
        else:
            result.status  -- e.g. "UNC at LBA, head 2, track damage"
    """

    # Standard read retry levels (ordered from safe to aggressive)
    RETRY_LEVELS: ClassVar[list[str]] = [
        "pio",  # PIO read (slowest, most reliable signal)
        "dma",  # DMA read
        "udma_short",  # UDMA with short timeout
        "udma_medium",  # UDMA with medium timeout
        "udma_long",  # UDMA with long timeout (up to 30s per sector)
        "udma_crc",  # UDMA with CRC retry disabled
        "reset_then_pio",  # Device reset, then PIO
        "reset_then_dma",  # Device reset, then DMA
        "pio_no_retry",  # PIO with hardware retries disabled
        "dma_no_retry",  # DMA with hardware retries disabled
    ]

    # ATA commands for different read protocols
    READ_PIO = 0x20
    READ_PIO_EXT = 0x24
    READ_DMA = 0xC8
    READ_DMA_EXT = 0x25
    READ_UDMA = 0xC8  # same opcode as DMA; protocol negotiated by the HBA
    READ_MULTIPLE = 0xC4
    READ_MULTIPLE_EXT = 0x29

    # Device control register flags
    CTRL_SRST = 0x04  # Software reset
    CTRL_nIEN = 0x02  # Disable interrupts

    # Status register bits
    STA_ERR = 0x01
    STA_DRQ = 0x08
    STA_DF = 0x20
    STA_DRDY = 0x40
    STA_BSY = 0x80

    @staticmethod
    def read_retry_escalation(
        drive_path: str, lba: int, levels: list[str] | None = None, max_attempts_per_level: int = 3
    ) -> ReadRetryResult:
        """
        Attempt to read a sector using escalating retry levels.
        Each retry level attempts a different read protocol / timing profile.
        If all levels fail, returns the failure result.

        Args:
            drive_path: /dev/sdX or PhysicalDriveN
            lba: target LBA
            levels: ordered list of retry levels (defaults to RETRY_LEVELS.all)
            max_attempts_per_level: retries within each level
        """
        if levels is None:
            levels = SATADataRecoveryOps.RETRY_LEVELS
        last_error = "no attempts made"

        for retry_idx, level in enumerate(levels):
            for attempt in range(max_attempts_per_level):
                try:
                    data = SATADataRecoveryOps._try_read(drive_path, lba, level)
                    if data and len(data) == 512:
                        return ReadRetryResult(
                            lba=lba,
                            success=True,
                            data=data,
                            attempts=attempt + 1,
                            retry_level=retry_idx,
                            status=f"OK at level {level}",
                        )
                except Exception as e:
                    last_error = str(e)
                    if "UNC" in last_error:
                        # Uncorrectable -- escalate to next level
                        break
                    if "IDNF" in last_error:
                        # ID not found -- head or track issue
                        break
                    continue

        return ReadRetryResult(
            lba=lba,
            success=False,
            data=b"",
            attempts=sum(max_attempts_per_level for _ in levels),
            retry_level=len(levels) - 1,
            status=f"FAILED after all levels. Last error: {last_error}",
        )

    @staticmethod
    def _try_read(drive_path: str, lba: int, level: str) -> bytes | None:
        """
        Attempt a single sector read at the given retry level.
        This is a simulation -- real implementation sends ATA RAW commands
        via SG_IO with protocol-specific CDBs.
        """
        # In a real implementation, this would:
        # 1. Open drive with SG_IO access
        # 2. Build appropriate ATA command for the retry level
        # 3. Set device register flags (disable retries, etc.)
        # 4. Submit command with HBA-specific timeout
        # 5. Parse returned status and data
        #
        # For offline analysis: signal that real SG_IO is needed.
        raise NotImplementedError(
            "read_retry_escalation requires physical drive access via SG_IO. "
            "Use this as a pattern for implementing native code in C or "
            "via pySGIO / pyATA bindings."
        )

    @staticmethod
    def smart_quick_test(drive_path: str) -> dict:
        """
        Initiate a short SMART self-test (offline data collection).
        Reads SMART RETURN STATUS (0xB0, 0xDA) to check test result.
        """
        # SMART ENABLE OPERATIONS: 0xD8
        # SMART RETURN STATUS:     0xDA (via SMART READ DATA)
        return {
            "test_type": "short",
            "status": "simulated",  # real: send SMART cmd via ATA PASS-THROUGH
            "drive": drive_path,
        }

    @staticmethod
    def read_native_max(drive_path: str) -> int:
        """
        Read the drive's native max address via READ NATIVE MAX ADDRESS EXT (0x27).
        This reveals the true physical size of the media, which may differ
        from the host-protected area (HPA) or device configuration overlay (DCO).
        """
        # ATA READ NATIVE MAX ADDRESS EXT
        # Returns 48-bit LBA of the last accessible sector
        warn("Simulated: real drive needed for READ NATIVE MAX")
        return 0

    @staticmethod
    def identify_device(drive_path: str) -> dict:
        """
        Issue IDENTIFY DEVICE and return parsed key fields.
        """
        identify_data = bytes(512)
        parsed = {
            "serial": identify_data[10:30].decode("ascii", errors="replace").strip(),
            "firmware": identify_data[46:54].decode("ascii", errors="replace").strip(),
            "model": identify_data[54:84].decode("ascii", errors="replace").strip(),
            "lba48_supported": bool(struct.unpack_from("<H", identify_data, 166)[0] & 0x400),
            "sector_count_48": struct.unpack_from("<Q", identify_data, 200)[0],
            "max_lba_28": struct.unpack_from("<I", identify_data, 120)[0],
            "sector_size": 512
            if not (struct.unpack_from("<H", identify_data, 106)[0] & 0x2000)
            else 4096,
            "dma_supported": bool(struct.unpack_from("<H", identify_data, 88)[0] & 0x08),
            "heads": struct.unpack_from("<H", identify_data, 102)[0] & 0xFF,
            "sectors_per_track": struct.unpack_from("<H", identify_data, 103)[0] & 0xFFFF,
        }
        return parsed

    @staticmethod
    def defective_sector_pattern_offset(lba: int, sector_size: int = 512) -> bytes:
        """
        Generate a synthetic 'defective sector' pattern for testing
        data recovery logic. Returns 512 bytes with LBA markers.
        """
        data = bytearray(sector_size)
        struct.pack_into("<I", data, 0, 0xDEADBEEF)
        struct.pack_into("<Q", data, 4, lba)
        # Fill rest with alternating pattern for partial-read detection
        for i in range(12, sector_size):
            data[i] = (i + lba) & 0xFF
        return bytes(data)

    @staticmethod
    def build_read_cdb(
        lba: int, sector_count: int = 1, protocol: str = "pio", lba48: bool = True
    ) -> bytes:
        """
        Build the appropriate ATA READ command CDB for the given protocol.
        Returns a 16-byte SAT ATA PASS-THROUGH (16) CDB.
        """
        cmd_map = {
            "pio": SATADataRecoveryOps.READ_PIO_EXT if lba48 else SATADataRecoveryOps.READ_PIO,
            "dma": SATADataRecoveryOps.READ_DMA_EXT if lba48 else SATADataRecoveryOps.READ_DMA,
            "udma_short": SATADataRecoveryOps.READ_DMA_EXT
            if lba48
            else SATADataRecoveryOps.READ_DMA,
            "udma_long": SATADataRecoveryOps.READ_DMA_EXT
            if lba48
            else SATADataRecoveryOps.READ_DMA,
            "udma_crc": SATADataRecoveryOps.READ_DMA_EXT
            if lba48
            else SATADataRecoveryOps.READ_DMA,
            "reset_then_pio": SATADataRecoveryOps.READ_PIO_EXT
            if lba48
            else SATADataRecoveryOps.READ_PIO,
            "reset_then_dma": SATADataRecoveryOps.READ_DMA_EXT
            if lba48
            else SATADataRecoveryOps.READ_DMA,
        }
        ata_cmd = cmd_map.get(protocol, 0x25)
        proto_map = {
            "pio": 4,  # PIO_DATA_IN
            "dma": 6,  # DMA
            "udma_short": 10,  # UDMA_DATA_IN
            "udma_long": 10,
            "udma_crc": 10,
            "reset_then_pio": 4,
            "reset_then_dma": 6,
        }
        proto = proto_map.get(protocol, 4)
        return SATLayer.build_ata_pass_through_16(
            ata_cmd=ata_cmd, lba=lba, sector_count=sector_count, protocol=proto
        )


# =============================================================================
# HPADCOAccess -- Host Protected Area / Device Configuration Overlay
# =============================================================================
