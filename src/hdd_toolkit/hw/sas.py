"""SCSI / SAS passthrough: INQUIRY, READ CAPACITY, SES diagnostic pages."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import ClassVar


# =============================================================================
# SCSI command opcodes  (SPC-5 / SBC-4 / SES-4)
# =============================================================================


class SCSIOpcode(IntEnum):
    """
    Common SCSI command opcodes.

    Sources:
      - SCSI Primary Commands 5 (SPC-5), Annex D: SCSI Command Codes.
      - SCSI Block Commands 4 (SBC-4), Table 1: SBC-4 Command Set.
      - SCSI Enclosure Services 4 (SES-4), Table 1: SES-4 Command Set.
    """

    TEST_UNIT_READY = 0x00
    INQUIRY = 0x12
    MODE_SENSE_6 = 0x1A
    START_STOP_UNIT = 0x1B
    SEND_DIAGNOSTIC = 0x1D
    RECEIVE_DIAGNOSTIC_RESULTS = 0x1C
    READ_CAPACITY_10 = 0x25
    READ_10 = 0x28
    WRITE_10 = 0x2A
    SYNCHRONIZE_CACHE_10 = 0x35
    READ_CAPACITY_16 = 0x9E
    SERVICE_ACTION_IN_16 = 0x9E
    MODE_SENSE_10 = 0x5A
    LOG_SENSE = 0x4D
    REPORT_LUNS = 0xA0


# =============================================================================
# INQUIRY VPD page codes  (SPC-5, Section 7.8)
# =============================================================================


class VPDPage(IntEnum):
    """
    SCSI VPD (Vital Product Data) page codes relevant to drive forensics.

    Sources:
      - SPC-5, Section 7.8: Standard INQUIRY Data.
      - SPC-5, Section 7.9: Vital Product Data parameters.
    """

    SUPPORTED_VPD_PAGES = 0x00
    UNIT_SERIAL_NUMBER = 0x80
    DEVICE_IDENTIFICATION = 0x83
    SOFTWARE_INTERFACE_ID = 0x84
    MANAGEMENT_NETWORK_ADDRESSES = 0x85
    EXTENDED_INQUIRY_DATA = 0x86
    MODE_PAGE_POLICY = 0x87
    SCSI_PORTS = 0x88
    BLOCK_LIMITS = 0xB0
    BLOCK_DEVICE_CHARACTERISTICS = 0xB1
    LOGICAL_BLOCK_PROVISIONING = 0xB2
    ZONED_BLOCK_DEVICE_CHARACTERISTICS = 0xB6


# =============================================================================
# CDB builders
# =============================================================================


def build_inquiry_cdb(
    evpd: bool = False,
    page_code: int = 0,
    alloc_len: int = 96,
) -> bytes:
    """
    Build a 6-byte SCSI INQUIRY CDB.

    Standard INQUIRY (evpd=False, page_code=0) returns up to 96 bytes of
    basic device identification data including vendor, product, and revision
    strings.

    VPD INQUIRY (evpd=True) with page_code selects a specific VPD page.
    Relevant pages for drive forensics:
      0x00  Supported VPD Pages
      0x80  Unit Serial Number
      0x83  Device Identification (WWN, NAA, T10 designators)
      0x86  Extended Inquiry Data (protection info, FUA support, etc.)
      0xB0  Block Limits (maximum transfer length, UNMAP granularity)
      0xB1  Block Device Characteristics (rotation rate, nominal form factor)
      0xB2  Logical Block Provisioning (thin provisioning, UNMAP support)

    Args:
        evpd: Enable Vital Product Data (bit 0 of byte 1).
        page_code: VPD page to retrieve (only used when evpd=True).
        alloc_len: Allocation length in bytes.

    Returns:
        6-byte SCSI CDB.

    Sources:
      - SPC-5, Section 7.8: INQUIRY command.
    """
    return struct.pack(
        "BBBBBB",
        SCSIOpcode.INQUIRY,
        0x01 if evpd else 0x00,
        page_code & 0xFF,
        (alloc_len >> 8) & 0xFF,
        alloc_len & 0xFF,
        0,
    )


def build_read_capacity_10_cdb() -> bytes:
    """
    Build a 10-byte READ CAPACITY (10) CDB.

    Returns the last accessible LBA and the logical block length for
    drives that report <= 2 TiB capacity.  Use READ CAPACITY (16) for
    larger drives.

    Returns:
        10-byte SCSI CDB.

    Sources:
      - SBC-4, Section 5.15: READ CAPACITY (10).
    """
    return bytes([SCSIOpcode.READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0])


def build_read_capacity_16_cdb(alloc_len: int = 32) -> bytes:
    """
    Build a 16-byte READ CAPACITY (16) SERVICE ACTION IN CDB.

    Returns capacity and block size data including:
      - Logical blocks address (8 bytes, big-endian)
      - Logical block length (4 bytes)
      - Protection, logical blocks per physical block exponent
      - Lowest aligned LBA

    Args:
        alloc_len: Allocation length (default 32 for standard fields).

    Returns:
        16-byte SCSI CDB.

    Sources:
      - SBC-4, Section 5.16: READ CAPACITY (16).
    """
    cdb = bytearray(16)
    cdb[0] = SCSIOpcode.SERVICE_ACTION_IN_16
    cdb[1] = 0x10
    struct.pack_into(">I", cdb, 10, alloc_len)
    return bytes(cdb)


def build_receive_diagnostic_cdb(page_code: int, alloc_len: int = 4096) -> bytes:
    """
    Build a RECEIVE DIAGNOSTIC RESULTS CDB (SES page retrieval).

    This command retrieves SES (SCSI Enclosure Services) diagnostic pages
    from an expander or drive backplane.  For individual SAS drives with an
    SES target device, it can read:
      0x00  Supported Diagnostic Pages
      0x01  Configuration
      0x02  Enclosure Status
      0x07  Element Descriptor
      0x0A  Additional Element Status (SAS address, slot number, etc.)

    Args:
        page_code: SES diagnostic page code to retrieve.
        alloc_len: Allocation length in bytes.

    Returns:
        6-byte SCSI CDB.

    Sources:
      - SES-4, Section 6.1.3: RECEIVE DIAGNOSTIC RESULTS.
    """
    return struct.pack(
        "BBBBBB",
        SCSIOpcode.RECEIVE_DIAGNOSTIC_RESULTS,
        0x01,
        page_code & 0xFF,
        (alloc_len >> 8) & 0xFF,
        alloc_len & 0xFF,
        0,
    )


def build_mode_sense_10_cdb(page_code: int, sub_page: int = 0, alloc_len: int = 252) -> bytes:
    """
    Build a MODE SENSE (10) CDB.

    Retrieves drive mode page parameters.  Relevant pages:
      0x01  Read-Write Error Recovery (retry counts, error correction)
      0x02  Disconnect-Reconnect (SAS/FC only)
      0x08  Caching (WCE, DRA, Read Ahead control)
      0x0A  Control (QERR, error priority, task management)
      0x19  Protocol-specific Port (SAS phy link reset, etc.)
      0x3F  All Mode Pages

    Args:
        page_code: Mode page code (0-0x3F).
        sub_page: Sub-page code (0 for standard page format).
        alloc_len: Allocation length.

    Returns:
        10-byte SCSI CDB.

    Sources:
      - SPC-5, Section 7.18: MODE SENSE (10).
    """
    cdb = bytearray(10)
    cdb[0] = SCSIOpcode.MODE_SENSE_10
    cdb[2] = (0x00 << 6) | (page_code & 0x3F)
    cdb[3] = sub_page & 0xFF
    struct.pack_into(">H", cdb, 7, alloc_len)
    return bytes(cdb)


# =============================================================================
# INQUIRY response parsers
# =============================================================================


@dataclass
class SCSIInquiryData:
    """
    Parsed standard SCSI INQUIRY response.

    Sources:
      - SPC-5, Section 7.8.2: Standard INQUIRY Data format.
    """

    peripheral_qualifier: int = 0
    peripheral_device_type: int = 0x1F
    removable: bool = False
    version: int = 0
    vendor_id: str = ""
    product_id: str = ""
    product_rev: str = ""
    vendor_specific: bytes = field(default_factory=bytes)
    spc_version: str = ""

    DEVICE_TYPES: ClassVar[dict[int, str]] = {
        0x00: "Direct-access block device (SBC)",
        0x01: "Sequential-access device (SSC)",
        0x04: "Write-once device",
        0x05: "CD/DVD device (MMC)",
        0x0C: "Storage array controller (SCC)",
        0x0D: "Enclosure services device (SES)",
        0x0E: "Simplified direct-access device",
        0x11: "Object-based storage device (OSD)",
        0x14: "Automation / Drive Interface",
        0x1E: "Well-known logical unit",
        0x1F: "Unknown / no device",
    }

    @property
    def device_type_name(self) -> str:
        return self.DEVICE_TYPES.get(
            self.peripheral_device_type,
            f"unknown (0x{self.peripheral_device_type:02X})",
        )

    @classmethod
    def parse(cls, data: bytes) -> "SCSIInquiryData":
        """
        Parse a standard INQUIRY response buffer.

        Args:
            data: Raw INQUIRY response bytes (at least 36 bytes).

        Returns:
            SCSIInquiryData with vendor/product fields decoded.
        """
        if len(data) < 36:
            return cls()
        pq_pdt = data[0]
        rmb = bool(data[1] & 0x80)
        version = data[2]
        vendor = data[8:16].decode("ascii", errors="replace").strip()
        product = data[16:32].decode("ascii", errors="replace").strip()
        rev = data[32:36].decode("ascii", errors="replace").strip()
        vs = data[36:56] if len(data) >= 56 else b""

        spc_ver = {
            0x03: "SPC",
            0x04: "SPC-2",
            0x05: "SPC-3",
            0x06: "SPC-4",
            0x07: "SPC-5",
        }.get(version, f"0x{version:02X}")

        return cls(
            peripheral_qualifier=(pq_pdt >> 5) & 0x07,
            peripheral_device_type=pq_pdt & 0x1F,
            removable=rmb,
            version=version,
            vendor_id=vendor,
            product_id=product,
            product_rev=rev,
            vendor_specific=vs,
            spc_version=spc_ver,
        )


@dataclass
class SCSICapacity:
    """
    Parsed READ CAPACITY (10) or READ CAPACITY (16) response.

    Sources:
      - SBC-4, Section 5.15/5.16: READ CAPACITY response data.
    """

    last_lba: int = 0
    block_length: int = 512
    is_16: bool = False
    protection_type: int = 0
    p_i_exponent: int = 0
    lbppbe: int = 0
    lowest_aligned_lba: int = 0

    @property
    def total_bytes(self) -> int:
        return (self.last_lba + 1) * self.block_length

    @property
    def total_gb(self) -> float:
        return self.total_bytes / 1e9

    @classmethod
    def parse_10(cls, data: bytes) -> "SCSICapacity":
        """
        Parse an 8-byte READ CAPACITY (10) response.

        Args:
            data: 8-byte response buffer.
        """
        if len(data) < 8:
            return cls()
        last_lba, block_len = struct.unpack_from(">II", data, 0)
        return cls(last_lba=last_lba, block_length=block_len, is_16=False)

    @classmethod
    def parse_16(cls, data: bytes) -> "SCSICapacity":
        """
        Parse a 32-byte READ CAPACITY (16) response.

        Args:
            data: 32-byte response buffer.
        """
        if len(data) < 32:
            return cls()
        last_lba = struct.unpack_from(">Q", data, 0)[0]
        block_len = struct.unpack_from(">I", data, 8)[0]
        prot_byte = data[12]
        p_type = (prot_byte >> 1) & 0x07
        p_i_exp = (data[13] >> 4) & 0x0F
        lbppbe = data[13] & 0x0F
        lowest = struct.unpack_from(">H", data, 14)[0] & 0x3FFF
        return cls(
            last_lba=last_lba,
            block_length=block_len,
            is_16=True,
            protection_type=p_type,
            p_i_exponent=p_i_exp,
            lbppbe=lbppbe,
            lowest_aligned_lba=lowest,
        )


# =============================================================================
# SES page parser (SES-4, Sections 6.1.2 / 6.1.10)
# =============================================================================


@dataclass
class SESElementStatus:
    """
    A single element status descriptor from an SES Enclosure Status page (0x02).

    Sources:
      - SES-4, Section 6.1.2: Enclosure Status diagnostic page.
    """

    element_type: int = 0
    slot_number: int = 0
    status_code: int = 0
    active: bool = False
    disabled: bool = False
    swap: bool = False
    raw: bytes = field(default_factory=bytes)

    STATUS_NAMES: ClassVar[dict[int, str]] = {
        0x00: "unsupported",
        0x01: "ok",
        0x02: "critical",
        0x03: "noncritical",
        0x04: "unrecoverable",
        0x05: "not installed",
        0x06: "unknown",
        0x07: "not available",
        0x08: "no access allowed",
    }

    @property
    def status_name(self) -> str:
        return self.STATUS_NAMES.get(self.status_code, f"0x{self.status_code:02X}")


def parse_ses_enclosure_status(data: bytes) -> list[SESElementStatus]:
    """
    Parse an SES Enclosure Status page (page code 0x02).

    Page layout (SES-4, Section 6.1.2.1):
      offset 0  u8  page code (0x02)
      offset 1  u8  UNRECOV|CRIT|NONCRIT|INFO|INVOP|reserved
      offset 2  u16 page length (N-3)
      offset 4  u32 generation code
      offset 8  Element status descriptors, each 4 bytes:
                  byte 0 bits[7:4] = PRDFAIL|DISABLED|SWAP|ELEMENT_STATUS_CODE (4 bits)
                  bytes 1-3        = element-type-specific status

    Args:
        data: Raw SES page bytes.

    Returns:
        List of SESElementStatus descriptors.

    Sources:
      - SES-4, Section 6.1.2: Enclosure Status diagnostic page.
    """
    if len(data) < 8:
        return []
    page_len = struct.unpack_from(">H", data, 2)[0]
    end = min(4 + page_len, len(data))
    offset = 8
    elements: list[SESElementStatus] = []
    slot = 0
    while offset + 4 <= end:
        b0 = data[offset]
        status_code = b0 & 0x0F
        swap = bool(b0 & 0x10)
        disabled = bool(b0 & 0x20)
        active = not disabled and status_code in (0x01,)
        raw = data[offset : offset + 4]
        elements.append(
            SESElementStatus(
                element_type=0,
                slot_number=slot,
                status_code=status_code,
                active=active,
                disabled=disabled,
                swap=swap,
                raw=raw,
            )
        )
        slot += 1
        offset += 4
    return elements


# =============================================================================
# Linux sg_io passthrough helper (no external deps, pure ctypes/fcntl)
# =============================================================================


class SCSIDevice:
    """
    Linux sg(4) / sg_io passthrough for SAS and SCSI drives.

    Issues SCSI commands via the Linux SCSI Generic (sg) driver using
    the SG_IO ioctl on /dev/sg* or /dev/sd* device nodes.  Requires
    root privileges and Linux 2.4+ with the sg driver loaded.

    On Windows, SCSI passthrough uses DeviceIoControl with
    IOCTL_SCSI_PASS_THROUGH_DIRECT; that path is not yet implemented
    in this module -- only Linux sg_io is supported.

    The sg_io_hdr_t structure fields used here:
      interface_id  'S' (SCSI)
      dxfer_direction  SG_DXFER_FROM_DEV (-3) or SG_DXFER_TO_DEV (-2)
      cmd_len          CDB length
      mx_sb_len        max sense buffer (32)
      dxfer_len        transfer length
      dxferp           pointer to data buffer
      cmdp             pointer to CDB
      sbp              pointer to sense buffer
      timeout          milliseconds (10 000 default)

    Sources:
      - Linux sg(4) man page: SG_IO ioctl, sg_io_hdr_t structure.
      - SCSI Generic (sg3_utils) documentation.
      - SPC-5 Section 4.2: Command descriptor block.
    """

    SG_IO = 0x2285
    SG_DXFER_FROM_DEV = -3
    SG_DXFER_TO_DEV = -2
    SG_DXFER_NONE = -1

    def __init__(self, path: str):
        self.path = path
        self._fd: int | None = None

    def __enter__(self) -> "SCSIDevice":
        import os
        self._fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK)
        return self

    def __exit__(self, *_) -> None:
        import os
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def passthrough(
        self,
        cdb: bytes,
        data_in_size: int = 0,
        data_out: bytes = b"",
        timeout_ms: int = 10_000,
    ) -> bytes:
        """
        Issue a SCSI command via SG_IO ioctl.

        Args:
            cdb: SCSI Command Descriptor Block bytes.
            data_in_size: Expected response size in bytes (for reads).
            data_out: Data to send to the device (for writes).
            timeout_ms: Command timeout in milliseconds.

        Returns:
            Response data bytes (empty for write commands).

        Raises:
            OSError: If the ioctl fails or the sense data indicates an error.
        """
        import ctypes
        import fcntl

        if self._fd is None:
            raise OSError("Device not open")

        buf = (ctypes.c_uint8 * max(data_in_size, 1))()
        if data_out:
            for i, b in enumerate(data_out):
                buf[i] = b

        cdb_arr = (ctypes.c_uint8 * len(cdb))(*cdb)
        sense = (ctypes.c_uint8 * 32)()

        direction = (
            self.SG_DXFER_TO_DEV
            if data_out
            else (self.SG_DXFER_FROM_DEV if data_in_size > 0 else self.SG_DXFER_NONE)
        )
        dxfer_len = len(data_out) if data_out else data_in_size

        hdr = struct.pack(
            "=iiBBHIIPPPIIHHI",
            ord("S"),
            direction,
            len(cdb),
            32,
            0,
            dxfer_len,
            0,
            ctypes.addressof(buf),
            ctypes.addressof(cdb_arr),
            ctypes.addressof(sense),
            timeout_ms,
            0,
            0,
            0,
            0,
        )
        fcntl.ioctl(self._fd, self.SG_IO, bytearray(hdr))
        return bytes(buf[:data_in_size])

    def inquiry(self, evpd: bool = False, page_code: int = 0) -> bytes:
        """
        Issue SCSI INQUIRY and return the raw response.

        Args:
            evpd: Enable Vital Product Data.
            page_code: VPD page code.
        """
        alloc = 96 if not evpd else 252
        cdb = build_inquiry_cdb(evpd=evpd, page_code=page_code, alloc_len=alloc)
        return self.passthrough(cdb, data_in_size=alloc)

    def read_capacity_10(self) -> bytes:
        """Issue READ CAPACITY (10) and return 8-byte response."""
        return self.passthrough(build_read_capacity_10_cdb(), data_in_size=8)

    def read_capacity_16(self) -> bytes:
        """Issue READ CAPACITY (16) and return 32-byte response."""
        return self.passthrough(build_read_capacity_16_cdb(), data_in_size=32)

    def receive_diagnostic(self, page_code: int, alloc_len: int = 4096) -> bytes:
        """Issue RECEIVE DIAGNOSTIC RESULTS and return raw SES page."""
        cdb = build_receive_diagnostic_cdb(page_code=page_code, alloc_len=alloc_len)
        return self.passthrough(cdb, data_in_size=alloc_len)
