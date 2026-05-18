"""Hitachi/HGST ATA vendor-specific commands for Service Area access."""

import struct
from enum import IntEnum

from hdd_toolkit.ata.commands import ATADevice, ATAError


class HitachiSAModule(IntEnum):
    """Hitachi/HGST Service Area module identifiers.

    Hitachi F/W architecture divides the SA into typed modules loaded
    at spinup.  ROM-resident modules (BOOT_CODE, TRANSLATOR) are always
    present; overlay modules are loaded on demand.  The G-list and P-list
    modules are critical for defect management and can be manipulated for
    data recovery or covert-storage purposes.

    Sources:
      - INVESTIGATION.md -- "ACE Lab PC-3000 UDMA -- Hitachi/HGST support":
          SA module type map for all Hitachi F3-derived drive families.
      - forum.hddguru.com -- "Hitachi HDD SA access via ATA vendor commands"
      - Equation Group nls_933w.dll analysis (Kaspersky 2015):
          Confirms BOOT_CODE (0x00) and TRANSLATOR (0x01) are target modules.
    """

    BOOT_CODE = 0x00
    TRANSLATOR = 0x01
    P_LIST = 0x02
    G_LIST = 0x03
    SMART_LOG = 0x04
    SELF_TEST_LOG = 0x05
    ERROR_LOG = 0x06
    ADAPTIVE_WRITES = 0x08
    ZONE_BIT = 0x0A


# ATA command / register constants shared by Hitachi VSC
_ATA_SMART = 0xB0
_SMART_READ_LOG = 0xD5
_SMART_WRITE_LOG = 0xD6
_CYL_LO = 0x4F
_CYL_HI = 0xC2

# Hitachi SA SMART log page addresses
HITACHI_SA_CMD_LOG = 0x02
HITACHI_SA_DATA_LOG = 0x03

# Hitachi SMART feature codes (feature register values)
HITACHI_FEAT_SA_READ = 0x45
HITACHI_FEAT_SA_WRITE = 0x46
HITACHI_FEAT_DIAG_MODE = 0xD0
HITACHI_FEAT_FW_MODE = 0xF8


class HitachiVSCClient:
    """Hitachi/HGST Service Area access via ATA SMART vendor commands.

    Hitachi drives (and HGST drives manufactured after the WD acquisition in
    2012) expose a two-level interface:
      1. Standard ATA SMART (0xB0) -- same as all other vendors.
      2. Enhanced vendor-specific SMART sub-commands that target individual
         SA modules by module ID.

    The SA command flow uses two SMART log pages:
      0x02 (HITACHI_SA_CMD_LOG)  -- write a 512-byte SA command descriptor to
                                    initiate a read or write operation.
      0x03 (HITACHI_SA_DATA_LOG) -- read/write the 512-byte data payload.

    SA command descriptor layout (512 bytes, written to log 0x02):
      byte 0     : operation code (0x01=read, 0x02=write)
      byte 1     : module type (HitachiSAModule value)
      bytes 2-3  : module length in sectors (0 = auto)
      bytes 4-5  : reserved
      bytes 6-509: reserved / write payload header

    Sources:
      - INVESTIGATION.md -- "ACE Lab PC-3000 UDMA -- Hitachi/HGST support"
      - forum.hddguru.com -- "Hitachi HDD SA access via ATA vendor commands"
      - Equation Group nls_933w.dll reverse engineering (Kaspersky 2015):
          Confirms BOOT_CODE and TRANSLATOR are SA targets for persistent implant.
    """

    _OP_READ = 0x01
    _OP_WRITE = 0x02
    _CHUNK_SECTORS = 1

    def __init__(self, device: ATADevice) -> None:
        self.dev = device

    def _build_sa_cmd_buf(self, op: int, module_id: int, length_sectors: int = 0) -> bytes:
        buf = bytearray(512)
        buf[0] = op & 0xFF
        buf[1] = module_id & 0xFF
        struct.pack_into("<H", buf, 2, length_sectors & 0xFFFF)
        return bytes(buf)

    def _write_cmd_log(self, buf: bytes) -> None:
        regs = {
            "features": HITACHI_FEAT_SA_WRITE,
            "count": 1,
            "lba_lo": HITACHI_SA_CMD_LOG,
            "cyl_lo": _CYL_LO,
            "cyl_hi": _CYL_HI,
            "dev": 0xA0,
            "cmd": _ATA_SMART,
        }
        self.dev.passthrough(regs, data_out=buf)

    def _read_data_log(self, sectors: int = 1) -> bytes:
        regs = {
            "features": HITACHI_FEAT_SA_READ,
            "count": sectors,
            "lba_lo": HITACHI_SA_DATA_LOG,
            "cyl_lo": _CYL_LO,
            "cyl_hi": _CYL_HI,
            "dev": 0xA0,
            "cmd": _ATA_SMART,
        }
        return self.dev.passthrough(regs, data_in_size=sectors * 512)

    def _write_data_log(self, buf: bytes) -> None:
        sectors = max(1, (len(buf) + 511) // 512)
        padded = buf.ljust(sectors * 512, b"\xFF")
        regs = {
            "features": HITACHI_FEAT_SA_WRITE,
            "count": sectors,
            "lba_lo": HITACHI_SA_DATA_LOG,
            "cyl_lo": _CYL_LO,
            "cyl_hi": _CYL_HI,
            "dev": 0xA0,
            "cmd": _ATA_SMART,
        }
        self.dev.passthrough(regs, data_out=padded)

    def read_module(self, module_id: int) -> bytes:
        """Read a Hitachi/HGST SA module by module ID.

        Issues a SMART WRITE LOG to log 0x02 with an SA read command
        descriptor, then reads payload from log 0x03 in 512-byte chunks
        until an all-0xFF sentinel is returned.
        """
        cmd_buf = self._build_sa_cmd_buf(self._OP_READ, module_id)
        self._write_cmd_log(cmd_buf)
        result = bytearray()
        for _ in range(64):
            chunk = self._read_data_log(self._CHUNK_SECTORS)
            if all(b == 0xFF for b in chunk):
                break
            result += chunk
        return bytes(result)

    def write_module(self, module_id: int, data: bytes) -> None:
        """Write data to a Hitachi/HGST SA module.

        Issues a SMART WRITE LOG to log 0x02 with an SA write command
        descriptor, then writes the payload to log 0x03 in 512-byte chunks.
        """
        length_sectors = max(1, (len(data) + 511) // 512)
        cmd_buf = self._build_sa_cmd_buf(self._OP_WRITE, module_id, length_sectors)
        self._write_cmd_log(cmd_buf)
        for i in range(0, len(data), 512):
            self._write_data_log(data[i : i + 512])

    def list_modules(self, max_module: int = 0x10) -> dict[int, bytes]:
        """Enumerate all readable SA modules up to max_module."""
        modules: dict[int, bytes] = {}
        for mod_id in range(max_module):
            try:
                data = self.read_module(mod_id)
                if data and not all(b == 0xFF for b in data):
                    modules[mod_id] = data
            except ATAError:
                continue
        return modules

    def probe_capabilities(self) -> dict:
        """Return a static capability report for Hitachi/HGST drives.

        Does not issue drive commands; reports the known VSC interface
        characteristics of the Hitachi F3 SA architecture.
        """
        return {
            "vendor": "Hitachi/HGST",
            "sa_cmd_log": hex(HITACHI_SA_CMD_LOG),
            "sa_data_log": hex(HITACHI_SA_DATA_LOG),
            "feat_sa_read": hex(HITACHI_FEAT_SA_READ),
            "feat_sa_write": hex(HITACHI_FEAT_SA_WRITE),
            "feat_diag_mode": hex(HITACHI_FEAT_DIAG_MODE),
            "feat_fw_mode": hex(HITACHI_FEAT_FW_MODE),
            "known_modules": {m.value: m.name for m in HitachiSAModule},
            "notes": (
                "BOOT_CODE (0x00) and TRANSLATOR (0x01) are confirmed NSA targets "
                "per Equation Group nls_933w.dll analysis (Kaspersky 2015)."
            ),
        }
