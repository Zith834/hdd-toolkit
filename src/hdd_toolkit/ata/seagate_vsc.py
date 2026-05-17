"""Seagate F3 Service Area access via SCT (Smart Command Transport)."""

import struct
from enum import IntEnum

from hdd_toolkit.ata.commands import ATADevice, ATAError


class SeagateSAModule(IntEnum):
    """Seagate F3 Service Area module IDs.

    ROM-resident modules (0x03, 0x0B) are loaded at power-on and remain in RAM
    throughout normal operation.  Physical overlay modules (0x1D-0x1F) are
    loaded on demand and contain ARM Thumb-2 code segments that extend the base
    ROM firmware.  Module 0x34 stores a packed XML (CONGEN) that defines drive
    personality and geometry.

    Sources:
      - forum.hddguru.com -- "Analysis of Seagate LOD firmware image"
      - forum.hddguru.com -- "How can I access Service Area?"
    """

    ROM_RESIDENT_0 = 0x03
    ROM_RESIDENT_1 = 0x0B
    PHYSICAL_OVERLAY_0 = 0x1D
    PHYSICAL_OVERLAY_1 = 0x1E
    PHYSICAL_OVERLAY_2 = 0x1F
    CONGEN_XML = 0x34


# Standard ATA SCT (Smart Command Transport) log addresses (ACS-2 section 8.9)
SCT_LOG_CMD = 0xE0
SCT_LOG_DATA = 0xE1

SMART_CMD = 0xB0
SMART_WRITE_LOG = 0xD6
SMART_READ_LOG = 0xD5

SCT_CYL_LO = 0x4F
SCT_CYL_HI = 0xC2

_SCT_SA_READ = 0x01
_SCT_SA_WRITE = 0x02
_SCT_SA_ACTION = 0xD0


class SeagateF3SCTClient:
    """
    Seagate F3 Service Area client using SCT (Smart Command Transport).

    Seagate F3 drives (Barracuda, IronWolf, Exos, Constellation families)
    store firmware overlays and configuration in the Service Area (SA) on the
    innermost platter tracks.  The SA is not accessible via normal LBA reads;
    access requires ATA SMART READ/WRITE LOG against the standard SCT log
    addresses:
      0xE0  SCT Command Transport -- write vendor command, read status
      0xE1  SCT Data Transfer     -- read payload after command completes

    A vendor SCT action code (0xD0) with sub-action 0x01 (read) or 0x02
    (write) targets individual SA modules by their module ID.  After issuing
    the command to log 0xE0, data is retrieved by reading from log 0xE1.

    Typical SA layout for Seagate F3:
      MOD 0x03  ROM-resident module 0 (always loaded at power-on)
      MOD 0x0B  ROM-resident module 1 (always loaded)
      MOD 0x1D  Physical Overlay File 0
      MOD 0x1E  Physical Overlay File 1
      MOD 0x1F  Physical Overlay File 2
      MOD 0x34  Packed CONGEN XML drive personality definition

    Sources:
      - forum.hddguru.com -- "Analysis of Seagate LOD firmware image"
      - forum.hddguru.com -- "How can I access Service Area?"
    """

    _CHUNK_SECTORS = 8

    def __init__(self, device: ATADevice):
        self.dev = device

    def _build_sa_cmd(self, sub_action: int, module_id: int) -> bytes:
        buf = bytearray(512)
        buf[0] = _SCT_SA_ACTION & 0xFF
        buf[1] = sub_action & 0xFF
        struct.pack_into("<H", buf, 2, module_id & 0xFFFF)
        return bytes(buf)

    def _sct_write_cmd(self, buf: bytes) -> None:
        regs = {
            "features": SMART_WRITE_LOG,
            "count": 1,
            "lba_lo": SCT_LOG_CMD,
            "cyl_lo": SCT_CYL_LO,
            "cyl_hi": SCT_CYL_HI,
            "dev": 0xA0,
            "cmd": SMART_CMD,
        }
        self.dev.passthrough(regs, data_out=buf)

    def _sct_read_data(self, sectors: int = 1) -> bytes:
        regs = {
            "features": SMART_READ_LOG,
            "count": sectors,
            "lba_lo": SCT_LOG_DATA,
            "cyl_lo": SCT_CYL_LO,
            "cyl_hi": SCT_CYL_HI,
            "dev": 0xA0,
            "cmd": SMART_CMD,
        }
        return self.dev.passthrough(regs, data_in_size=sectors * 512)

    def _sct_write_data(self, buf: bytes) -> None:
        sectors = max(1, (len(buf) + 511) // 512)
        padded = buf.ljust(sectors * 512, b"\xFF")
        regs = {
            "features": SMART_WRITE_LOG,
            "count": sectors,
            "lba_lo": SCT_LOG_DATA,
            "cyl_lo": SCT_CYL_LO,
            "cyl_hi": SCT_CYL_HI,
            "dev": 0xA0,
            "cmd": SMART_CMD,
        }
        self.dev.passthrough(regs, data_out=padded)

    def read_module(self, module_id: int) -> bytes:
        """Read a Seagate F3 Service Area module by module ID."""
        cmd = self._build_sa_cmd(_SCT_SA_READ, module_id)
        self._sct_write_cmd(cmd)
        result = bytearray()
        for _ in range(64):
            chunk = self._sct_read_data(self._CHUNK_SECTORS)
            if all(b == 0xFF for b in chunk):
                break
            result += chunk
        return bytes(result)

    def write_module(self, module_id: int, data: bytes) -> None:
        """Write a Seagate F3 Service Area module by module ID."""
        cmd = self._build_sa_cmd(_SCT_SA_WRITE, module_id)
        self._sct_write_cmd(cmd)
        chunk_size = 512
        for i in range(0, len(data), chunk_size):
            self._sct_write_data(data[i : i + chunk_size])

    def list_modules(self, max_module: int = 0x40) -> dict[int, bytes]:
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
