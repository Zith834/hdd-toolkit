"""Serial diagnostic console, mask ROM menu, and GDB stub helpers (ACSAC'13 §2.1).

Sources:
  - Zaddach et al., "Implementation and Implications of a Stealth Hard-Drive
    Backdoor", ACSAC 2013, section 2.1.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

from hdd_toolkit.core.utils import ok, warn
from hdd_toolkit.firmware.write_hook import ArmSoftwareBreakpoint


class _MockSerial:
    def __init__(self, *_args, **_kwargs):
        self.writes: list[bytes] = []
        self._read_buf = bytearray()

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        return None

    def read(self, size: int = 1) -> bytes:
        if size <= 0:
            return b""
        if not self._read_buf:
            return b""
        out = bytes(self._read_buf[:size])
        del self._read_buf[:size]
        return out

    def readline(self) -> bytes:
        if not self._read_buf:
            return b""
        try:
            idx = self._read_buf.index(0x0A)
            out = bytes(self._read_buf[: idx + 1])
            del self._read_buf[: idx + 1]
            return out
        except ValueError:
            out = bytes(self._read_buf)
            self._read_buf.clear()
            return out

    def queue_read(self, chunks: Iterable[bytes]) -> None:
        for chunk in chunks:
            self._read_buf.extend(chunk)

    def close(self) -> None:
        self._read_buf.clear()


class DriveSerialConsole:
    """Drive UART console transport (ACSAC'13 §2.1)."""

    PROMPT: ClassVar[str] = "F3 T>"

    def __init__(self, port: str, baud: int = 38400, timeout: float = 2.0):
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self._ser = None

    def open(self) -> None:
        if self._ser is not None:
            return
        try:
            import serial as _serial

            self._ser = _serial.Serial(
                port=self.port,
                baudrate=self.baud,
                bytesize=8,
                stopbits=1,
                parity="N",
                timeout=self.timeout,
            )
            ok(f"Serial console open: {self.port} @ {self.baud} baud")
        except Exception:
            warn("Falling back to mock serial transport")
            self._ser = _MockSerial()

    def close(self) -> None:
        if self._ser is None:
            return
        with_exception = False
        try:
            self._ser.close()
        except Exception:
            with_exception = True
        self._ser = None
        if with_exception:
            warn("Serial console close reported an error")

    def _ensure_open(self) -> None:
        if self._ser is None:
            self.open()

    def _read_until_prompt(self) -> str:
        self._ensure_open()
        response = bytearray()
        prompt = self.PROMPT.encode()
        for _ in range(256):
            chunk = self._ser.readline() if hasattr(self._ser, "readline") else self._ser.read(1)
            if not chunk:
                break
            response.extend(chunk)
            if prompt in response:
                break
        return response.decode(errors="replace")

    def send_command(self, cmd: str) -> str:
        self._ensure_open()
        self._ser.write((cmd + "\r\n").encode())
        if hasattr(self._ser, "flush"):
            self._ser.flush()
        return self._read_until_prompt()

    @staticmethod
    def _parse_hex_bytes(text: str, max_len: int | None = None) -> bytes:
        hex_chars = "".join(ch for ch in text if ch in "0123456789abcdefABCDEF")
        if len(hex_chars) % 2 == 1:
            hex_chars = hex_chars[:-1]
        raw = bytes.fromhex(hex_chars) if hex_chars else b""
        if max_len is None:
            return raw
        return raw[:max_len]

    def dump_memory(self, addr: int, length: int) -> bytes:
        resp = self.send_command(f"md 0x{addr:08X} {length}")
        return self._parse_hex_bytes(resp, max_len=length)

    def write_memory(self, addr: int, data: bytes) -> bool:
        for offset, value in enumerate(data):
            resp = self.send_command(f"mw 0x{addr + offset:08X} 0x{value:02X}")
            if "ERR" in resp.upper():
                return False
        return True


class MaskRomBootMenu:
    """Mask ROM boot menu access used before main firmware starts (§2.1)."""

    BOOT_MENU_BREAK: ClassVar[bytes] = b"\x08"
    STUB_SIZE_BYTES: ClassVar[int] = 3482

    def __init__(self, console: DriveSerialConsole):
        self.console = console

    def enter_boot_menu(self) -> bool:
        """Send the boot-break sequence and return True when menu prompt is observed."""
        self.console.open()
        self.console._ser.write(self.BOOT_MENU_BREAK)
        if hasattr(self.console._ser, "flush"):
            self.console._ser.flush()
        resp = self.console.send_command("")
        return "BOOT" in resp.upper() or ">" in resp

    def read_memory(self, addr: int, count: int) -> bytes:
        resp = self.console.send_command(f"rm 0x{addr:08X} {count}")
        return DriveSerialConsole._parse_hex_bytes(resp, max_len=count)

    def write_memory(self, addr: int, data: bytes) -> bool:
        for offset, value in enumerate(data):
            resp = self.console.send_command(f"wm 0x{addr + offset:08X} 0x{value:02X}")
            if "ERR" in resp.upper():
                return False
        return True

    def inject_gdb_stub(self, stub_bytes: bytes, load_addr: int) -> bool:
        """Write stub bytes to SRAM, set PC to stub entry, and report success."""
        if len(stub_bytes) > self.STUB_SIZE_BYTES:
            warn("Stub size exceeds expected 3.4kB payload")
        if not self.write_memory(load_addr, stub_bytes):
            return False
        resp = self.console.send_command(f"setpc 0x{load_addr:08X}")
        ok(f"Injected GDB stub at 0x{load_addr:08X}")
        return "ERR" not in resp.upper()


class GdbStub:
    """Minimal GDB RSP client bound to injected stateless SRAM stub (§2.1)."""

    STUB_IS_STATELESS: ClassVar[bool] = True

    def __init__(self, console: DriveSerialConsole, stub_addr: int):
        self.console = console
        self.stub_addr = stub_addr
        self._breakpoints: dict[int, int] = {}

    @staticmethod
    def _rsp_checksum(payload: bytes) -> bytes:
        return f"{sum(payload) % 256:02x}".encode("ascii")

    def _send_packet(self, payload: bytes) -> str:
        self.console.open()
        packet = b"$" + payload + b"#" + self._rsp_checksum(payload)
        self.console._ser.write(packet)
        if hasattr(self.console._ser, "flush"):
            self.console._ser.flush()

        ack = self.console._ser.read(1)
        if ack != b"+":
            return ""

        lead = self.console._ser.read(1)
        if lead != b"$":
            return lead.decode(errors="replace") if lead else ""

        resp = bytearray()
        while True:
            ch = self.console._ser.read(1)
            if not ch or ch == b"#":
                break
            resp.extend(ch)
        self.console._ser.read(2)
        self.console._ser.write(b"+")
        return resp.decode(errors="replace")

    def read_memory(self, addr: int, length: int) -> bytes:
        resp = self._send_packet(f"m{addr:x},{length:x}".encode("ascii"))
        if not resp:
            return b""
        try:
            return bytes.fromhex(resp)
        except ValueError:
            return b""

    def write_memory(self, addr: int, data: bytes) -> bool:
        payload = f"M{addr:x},{len(data):x}:{data.hex()}".encode("ascii")
        return self._send_packet(payload).startswith("OK")

    def read_registers(self) -> dict[str, int]:
        resp = self._send_packet(b"g")
        if not resp:
            return {}

        raw = bytes.fromhex(resp)
        names = [*(f"r{i}" for i in range(16)), "cpsr"]
        regs: dict[str, int] = {}
        for i, name in enumerate(names):
            start = i * 4
            if start + 4 > len(raw):
                break
            regs[name] = int.from_bytes(raw[start : start + 4], "little")
        return regs

    def set_breakpoint(self, addr: int) -> bool:
        """Install a software breakpoint at address `addr`, saving original instruction."""
        original = self.read_memory(addr, 4)
        if len(original) != 4:
            return False
        self._breakpoints[addr] = int.from_bytes(original, "little")
        bp = ArmSoftwareBreakpoint(addr, self._breakpoints[addr])
        return self.write_memory(addr, bp.encode_undef_instruction())

    def clear_breakpoint(self, addr: int) -> bool:
        if addr not in self._breakpoints:
            return False
        original = self._breakpoints.pop(addr)
        return self.write_memory(addr, original.to_bytes(4, "little"))
