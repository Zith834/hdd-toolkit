"""SCSI-ATA Translation (SAT-4) layer for SAS drives."""

import struct
from enum import IntEnum


class SATCmd(IntEnum):
    """SCSI operation codes used in SAT (SPC-4 / SAT-4) pass-through."""

    ATA_PASS_THROUGH_12 = 0xA1  # 12-byte CDB
    ATA_PASS_THROUGH_16 = 0x85  # 16-byte CDB
    ATA_PASS_THROUGH_32 = 0x7F  # variable-length CDB (SSC)
    READ_10 = 0x28
    WRITE_10 = 0x2A
    READ_16 = 0x88
    WRITE_16 = 0x8A
    INQUIRY = 0x12
    MODE_SENSE_10 = 0x5A
    READ_CAPACITY_10 = 0x25
    READ_CAPACITY_16 = 0x9E
    REPORT_LUNS = 0xA0
    REQUEST_SENSE = 0x03
    SYNCHRONIZE_CACHE_10 = 0x35
    SYNCHRONIZE_CACHE_16 = 0x91
    SERVICE_ACTION_IN_12 = 0x9E  # sub-pages: 0x10 = READ CAPACITY, 0x0B = SECURITY PROTOCOL
    SECURITY_PROTOCOL_IN = 0xA2
    SECURITY_PROTOCOL_OUT = 0xB5


class SATLayer:
    """
    SCSI-ATA Translation (SAT-4) layer for SAS drives.
    Builds CDBs for ATA pass-through commands, translates ATA status to
    SCSI sense data, and provides high-level helpers for common ATA ops
    via a SAS transport.

    Useful for enterprise drives (Seagate Enterprise, WD Gold/Ultrastar SAS)
    that present a SCSI logical unit but speak ATA internally.

    Usage:
        sat = SATLayer()
        # Generate a SAT-16 CDB for an ATA READ SECTORS EXT
        cdb = sat.build_ata_pass_through_16(
            ata_cmd=0x25,   # READ DMA EXT
            lba=0x1000, sector_count=1,
            proto=SATLayer.PROTO_PIO_DATA_IN)
        # Send cdb via the SAS HBA's SG_IO / BSG ioctl

    Sources:
      - INVESTIGATION.md  -- "SAT-4 Standard (T10/2088-D, r06)":
          Definitive 283-page standard for SCSI=ATA command mapping
      - INVESTIGATION.md  -- "SAT-3 Project Proposal (T10/08-224r0)":
          ATA security translation, NCQ control, persistent reservations
      - INVESTIGATION.md  -- "SAT ATA Information VPD Page (T10/04-219r1)":
          SAT translator identification via INQUIRY VPD
      - INVESTIGATION.md  -- "scsi_satl(8)":
          Linux tool for testing SAT compliance
    """

    # ATA register layout inside SAT-12/16 CDBs (per T10/ACS-4)
    # SAT-16 CDB structure (offset, size):
    #   [1]   ATA FLAGS: bit 7=CC (continuum), bit 5-0=protocol
    #   [2]   features (7:0)
    #   [3]   sector count (7:0)
    #   [4]   LBA low  (7:0)
    #   [5]   LBA mid  (7:0)
    #   [6]   LBA high (7:0)
    #   [7]   device
    #   [8]   command
    #   [9]   features (15:8) / count (15:8)
    #   [10]  LBA low  (15:8)
    #   [11]  LBA mid  (15:8)
    #   [12]  LBA high (15:8)
    #   [13]  device
    #   [14]  control (shadow)
    #   [15]  control
    # Return: 0..504 bytes of ATA data (PIO), + ATA status in descriptor

    PROTO_HARD_RESET = 0  # 00000
    PROTO_SRST = 1  # 00001
    PROTO_PIO_DATA_IN = 4  # 00100
    PROTO_PIO_DATA_OUT = 5  # 00101
    PROTO_DMA = 6  # 00110
    PROTO_DMA_QUEUED = 7  # 00111
    PROTO_DEVICE_DIAG = 8  # 01000
    PROTO_DEVICE_RESET = 9  # 01001
    PROTO_UDMA_DATA_IN = 10  # 01010
    PROTO_UDMA_DATA_OUT = 11  # 01011
    PROTO_FPDMA = 12  # 01100
    PROTO_INTERRUPT_NO_DATA = 13  # 01101
    PROTO_RETURN_RESP_INFO = 15  # 01111

    # Fixed sense data for ATA PASS-THROUGH CHECK CONDITION
    SENSE_ATA_PT_ERROR = bytes(
        [
            0x72,  # RESPONSE CODE: Current, descriptor
            0x0E,  # SENSE KEY: DATA PROTECT (miscompare)
            0x00,
            0x00,  # ASC/ASCQ
            0x00,  # FRU
            0x0A,  # SENSE KEY SPECIFIC (10 bytes follow)
            0x09,
            0x0C,
            0x00,  # ATA RETURN descriptor
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ]
    )

    @staticmethod
    def build_ata_pass_through_16(
        ata_cmd: int,
        lba: int = 0,
        sector_count: int = 1,
        protocol: int = 4,  # PIO_DATA_IN
        features: int = 0,
        device: int = 0,
        control: int = 0,
    ) -> bytes:
        """Build a 16-byte SAT ATA PASS-THROUGH CDB (opcode 0x85)."""
        ccb = bytearray(16)
        ccb[0] = 0x85  # ATA PASS-THROUGH (16)
        ccb[1] = 0x80 | (protocol & 0x1F)  # flags + protocol
        ccb[2] = features & 0xFF
        ccb[3] = sector_count & 0xFF
        ccb[4] = lba & 0xFF
        ccb[5] = (lba >> 8) & 0xFF
        ccb[6] = (lba >> 16) & 0xFF
        ccb[7] = device & 0xF0  # bits 7-4 = device, bits 3-0 = head
        ccb[8] = ata_cmd & 0xFF
        ccb[9] = (features >> 8) & 0xFF
        ccb[10] = (lba >> 24) & 0xFF
        ccb[11] = (lba >> 32) & 0xFF
        ccb[12] = (lba >> 40) & 0xFF
        ccb[13] = (device >> 4) & 0x0F
        ccb[14] = control & 0xFF
        ccb[15] = 0x00
        return bytes(ccb)

    @staticmethod
    def build_ata_pass_through_12(
        ata_cmd: int,
        lba: int = 0,
        sector_count: int = 1,
        protocol: int = PROTO_PIO_DATA_IN,
        features: int = 0,
    ) -> bytes:
        """Build a 12-byte SAT ATA PASS-THROUGH CDB (opcode 0xA1)."""
        ccb = bytearray(12)
        ccb[0] = 0xA1
        ccb[1] = protocol & 0x1F
        ccb[2] = features & 0xFF
        ccb[3] = sector_count & 0xFF
        ccb[4] = lba & 0xFF
        ccb[5] = (lba >> 8) & 0xFF
        ccb[6] = (lba >> 16) & 0xFF
        ccb[7] = ata_cmd & 0xFF
        ccb[8] = 0x00
        ccb[9] = 0x00
        ccb[10] = 0x00
        ccb[11] = 0x00
        return bytes(ccb)

    @staticmethod
    def build_ata_pass_through_32(
        ata_cmd: int,
        lba: int = 0,
        sector_count: int = 1,
        protocol: int = PROTO_PIO_DATA_IN,
        features: int = 0,
        device: int = 0,
        control: int = 0,
    ) -> bytes:
        """Build a 32-byte variable-length SAT ATA PASS-THROUGH CDB (opcode 0x7F)."""
        ccb = bytearray(32)
        ccb[0] = 0x7F  # variable-length CDB
        ccb[1] = 0x00
        ccb[2] = 0x00
        ccb[3] = 0x06  # additional CDB length (24 bytes follow)
        ccb[4] = 0x1C  # service action: ATA PASS-THROUGH (32)
        ccb[5] = 0x80 | (protocol & 0x1F)
        ccb[6] = features & 0xFF
        ccb[7] = sector_count & 0xFF
        ccb[8] = lba & 0xFF
        ccb[9] = (lba >> 8) & 0xFF
        ccb[10] = (lba >> 16) & 0xFF
        ccb[11] = device & 0xF0
        ccb[12] = ata_cmd & 0xFF
        ccb[13] = (features >> 8) & 0xFF
        ccb[14] = (lba >> 24) & 0xFF
        ccb[15] = (lba >> 32) & 0xFF
        ccb[16] = (lba >> 40) & 0xFF
        ccb[17] = (device >> 4) & 0x0F
        ccb[18] = control & 0xFF
        ccb[19] = 0x00  # ATA status
        ccb[20:] = b"\x00" * 12
        return bytes(ccb)

    @staticmethod
    def build_read_16(
        lba: int, sector_count: int, prot_info: bool = False, fua: bool = False, dpo: bool = False
    ) -> bytes:
        """Build a SCSI READ (16) CDB."""
        cdb = bytearray(16)
        cdb[0] = 0x88  # READ (16)
        cdb[1] = (int(dpo) << 4) | (int(fua) << 3) | int(prot_info)
        struct.pack_into(">Q", cdb, 2, lba)
        struct.pack_into(">I", cdb, 10, sector_count)
        cdb[14:16] = b"\x00\x00"
        return bytes(cdb)

    @staticmethod
    def build_write_16(
        lba: int, sector_count: int, prot_info: bool = False, fua: bool = False, dpo: bool = False
    ) -> bytes:
        """Build a SCSI WRITE (16) CDB."""
        cdb = bytearray(16)
        cdb[0] = 0x8A  # WRITE (16)
        cdb[1] = (int(dpo) << 4) | (int(fua) << 3) | int(prot_info)
        struct.pack_into(">Q", cdb, 2, lba)
        struct.pack_into(">I", cdb, 10, sector_count)
        cdb[14:16] = b"\x00\x00"
        return bytes(cdb)

    @staticmethod
    def build_inquiry(evpd: bool = False, page_code: int = 0, alloc_len: int = 96) -> bytes:
        """Build a SCSI INQUIRY CDB (6 bytes, opcode 0x12)."""
        cdb = bytearray(6)
        cdb[0] = 0x12
        cdb[1] = (1 if evpd else 0) << 0
        cdb[2] = page_code & 0xFF
        struct.pack_into(">H", cdb, 3, alloc_len)
        cdb[5] = 0
        return bytes(cdb)

    @staticmethod
    def build_read_capacity_16() -> bytes:
        """Build a SCSI READ CAPACITY (16) CDB -- returns 0x200-byte block count + size."""
        cdb = bytearray(16)
        cdb[0] = 0x9E
        cdb[1] = 0x10  # SERVICE ACTION: READ CAPACITY
        cdb[2:] = b"\x00" * 12
        cdb[13] = 0x20  # alloc len = 32 bytes
        return bytes(cdb)

    @staticmethod
    def parse_ata_return_descriptor(data: bytes) -> dict:
        """
        Parse the ATA RETURN descriptor appended to the sense data after
        a failed ATA PASS-THROUGH command. Returns dict of ATA registers.
        """
        if len(data) < 12:
            return {}
        return {
            "error": data[0],
            "sector_count": data[2],
            "lba_low": data[4],
            "lba_mid": data[6],
            "lba_high": data[8],
            "device": data[10],
            "status": data[11] & data[1] if len(data) > 11 else 0,
        }

    @staticmethod
    def ata_status_to_sense(ata_status: int, ata_error: int) -> bytes:
        """
        Convert ATA status register to SCSI sense data (descriptor format).
        This is what SAT targets return when an ATA command fails.
        """
        sense_key = 0x0E  # MISCOMPARE (generic ATA passthrough error)
        asc = 0x00
        ascq = 0x1D  # ATA PASS-THROUGH INFORMATION AVAILABLE

        if ata_status & 0x01:  # ERR bit
            sense_key = 0x01  # RECOVERED ERROR (for corrected ECC errors)
            asc = 0x17
            ascq = 0x01
        if ata_status & 0x08:  # DRQ -- device wants data transfer
            sense_key = 0x04  # HARDWARE ERROR
            asc = 0x08
            ascq = 0x03
        if ata_status & 0x20:  # DF -- device fault
            sense_key = 0x04  # HARDWARE ERROR
            asc = 0x44
            ascq = 0x00
        if ata_status & 0x40:  # DRDY -- drive ready
            pass
        if ata_status & 0x80:  # BSY -- busy
            sense_key = 0x02  # NOT READY
            asc = 0x04
            ascq = 0x02  # LOGICAL UNIT NOT READY IN TRANSITION

        sense = bytearray(24)
        sense[0] = 0x72  # RESPONSE CODE: Current, descriptor format
        sense[1] = sense_key & 0x0F
        sense[2] = asc & 0xFF
        sense[3] = ascq & 0xFF
        # ATA return descriptor (descriptor code 0x09)
        sense[8] = 0x09
        sense[9] = 0x0C  # additional length (12 bytes)
        sense[10] = ata_error & 0xFF  # ERROR register
        sense[11] = 0x00  # SECTOR COUNT (7:0)
        sense[12] = 0x00  # SECTOR COUNT (15:8)
        sense[13] = 0x00  # LBA LOW (7:0)
        sense[14] = 0x00  # LBA LOW (15:8)
        sense[15] = 0x00  # LBA MID (7:0)
        sense[16] = 0x00  # LBA MID (15:8)
        sense[17] = 0x00  # LBA HIGH (7:0)
        sense[18] = 0x00  # LBA HIGH (15:8)
        sense[19] = ata_status & 0xFF
        return bytes(sense)
