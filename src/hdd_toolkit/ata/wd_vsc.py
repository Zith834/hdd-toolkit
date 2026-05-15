"""Western Digital Vendor Specific Commands (VSCs) via SMART LOG 0xBE."""

import struct
from enum import IntEnum

from hdd_toolkit.ata.commands import ATADevice


class WD_VSC(IntEnum):  # noqa: N801
    READ_RAM = 0x01
    WRITE_RAM = 0x02
    READ_OVERLAY = 0x10
    WRITE_OVERLAY = 0x11
    EXEC_CODE = 0x20
    GET_VSC_LIST = 0xFF


WD_LOG_ADDR = 0xBE
ATA_SMART = 0xB0
SMART_WRITE = 0xD6
SMART_READ = 0xD5
CYL_LO = 0x4F
CYL_HI = 0xC2


class WDVSCClient:
    """
    Send Western Digital Vendor Specific Commands via SMART READ/WRITE LOG
    at the special log address 0xBE.
    """

    def __init__(self, device: ATADevice):
        self.dev = device

    def _build_vsc_buf(
        self, vsc_id: int, mode: int, addr: int = 0, size: int = 0, payload: bytes = b""
    ) -> bytes:
        buf = bytearray(512)
        buf[0] = vsc_id
        buf[1] = mode  # 0=read, 1=write
        struct.pack_into("<II", buf, 2, addr, size)
        if payload:
            buf[10 : 10 + len(payload)] = payload
        return bytes(buf)

    def _smart_write(self, vsc_buf: bytes) -> bytes:
        regs = {
            "features": SMART_WRITE,
            "count": 1,
            "lba_lo": WD_LOG_ADDR,
            "cyl_lo": CYL_LO,
            "cyl_hi": CYL_HI,
            "dev": 0xA0,
            "cmd": ATA_SMART,
        }
        return self.dev.passthrough(regs, data_out=vsc_buf)

    def _smart_read(self, size: int = 512) -> bytes:
        regs = {
            "features": SMART_READ,
            "count": 1,
            "lba_lo": WD_LOG_ADDR,
            "cyl_lo": CYL_LO,
            "cyl_hi": CYL_HI,
            "dev": 0xA0,
            "cmd": ATA_SMART,
        }
        return self.dev.passthrough(regs, data_in_size=size)

    # == Public API ===========================================================

    def read_ram(self, addr: int, size: int) -> bytes:
        """Read `size` bytes from drive RAM at `addr`."""
        result = bytearray()
        chunk = 504  # max safe payload per 512-byte sector minus header
        offset = 0
        while offset < size:
            to_read = min(chunk, size - offset)
            vsc = self._build_vsc_buf(WD_VSC.READ_RAM, 0, addr + offset, to_read)
            self._smart_write(vsc)
            data = self._smart_read(to_read)
            result += data[:to_read]
            offset += to_read
        return bytes(result)

    def write_ram(self, addr: int, data: bytes) -> None:
        """Write `data` to drive RAM at `addr`."""
        chunk = 500
        offset = 0
        while offset < len(data):
            chunk_data = data[offset : offset + chunk]
            vsc = self._build_vsc_buf(
                WD_VSC.WRITE_RAM, 1, addr + offset, len(chunk_data), chunk_data
            )
            self._smart_write(vsc)
            offset += len(chunk_data)

    def read_overlay(self, module_id: int) -> bytes:
        """Read a service-area overlay module."""
        vsc = self._build_vsc_buf(WD_VSC.READ_OVERLAY, 0, module_id, 0)
        self._smart_write(vsc)
        # Overlay modules can be large; read in 4KB chunks
        result = bytearray()
        for _ in range(64):  # up to 256 KB
            chunk = self._smart_read(4096)
            if all(b == 0xFF for b in chunk):
                break
            result += chunk
        return bytes(result)

    def write_overlay(self, module_id: int, data: bytes) -> None:
        """Write a service-area overlay module."""
        chunk_size = 500
        for i in range(0, len(data), chunk_size):
            chunk = data[i : i + chunk_size]
            vsc = self._build_vsc_buf(WD_VSC.WRITE_OVERLAY, 1, module_id, i, chunk)
            self._smart_write(vsc)

    def list_vscs(self) -> bytes:
        """Request the VSC list (returns raw 512-byte response)."""
        vsc = self._build_vsc_buf(WD_VSC.GET_VSC_LIST, 0)
        self._smart_write(vsc)
        return self._smart_read()

    def verify_patch(self, addr: int, expected: bytes) -> bool:
        """Read back `addr` and confirm it matches `expected`."""
        actual = self.read_ram(addr, len(expected))
        return actual == expected
