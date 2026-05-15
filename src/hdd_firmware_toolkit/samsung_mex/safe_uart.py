import struct

from hdd_firmware_toolkit.core.utils import hdr, info, ok, warn
from hdd_firmware_toolkit.samsung_mex.memory_map import SamsungMEXMap


class SamsungSafeUARTClient:
    """
    SAFE-mode UART protocol for Samsung MEX SSDs (TheMissingManual, Layer 7).

    Activation:
        Short GPIO_SAFE_MODE (bit 17) to GND BEFORE power-on.
        The SSD boots with only mex1 active, reports 500 MB size (= RAM),
        serial number SN000000000000, no NAND mounted.
        UART appears on the two pins adjacent to the SAFE/JTAG header,
        3.3 V logic, 115200 8N1.

    Commands:
        rr <8 hex digits>            Read 32-bit word
        rw <8 hex digits> <8 hex>    Write 32-bit word
        ~<exactly 1 MB firmware>~    Firmware update

    NOTE: This UART is designed for a proprietary Samsung tool.
    HDD Serial Commander (http://www.hddserialcommander.com/) wraps the
    commands via a SQLite database.
    """

    def __init__(self, port: str, timeout: float = 2.0):
        try:
            import serial as _serial
        except ImportError:
            raise RuntimeError("pyserial required: pip install pyserial")
        self._ser = _serial.Serial(
            port=port,
            baudrate=SamsungMEXMap.UART_BAUD,
            bytesize=8,
            stopbits=1,
            parity="N",
            timeout=timeout,
        )
        ok(f"SAFE UART open: {port}  @ {SamsungMEXMap.UART_BAUD} 8N1  3.3V")

    def read_word(self, addr: int) -> int:
        """rr: read 32-bit word from `addr`. Returns integer."""
        cmd = f"rr{addr:08X}\r\n".encode()
        self._ser.write(cmd)
        self._ser.flush()
        resp = self._ser.read(12).strip()
        try:
            return int(resp[-8:], 16)
        except (ValueError, IndexError):
            raise OSError(f"Bad UART response for rr 0x{addr:08X}: {resp!r}")

    def write_word(self, addr: int, value: int) -> None:
        """rw: write 32-bit word to `addr`. No return value."""
        cmd = f"rw{addr:08X}{value:08X}\r\n".encode()
        self._ser.write(cmd)
        self._ser.flush()

    def read_range(self, addr: int, size: int) -> bytes:
        """Read `size` bytes via repeated rr commands (4 bytes/round-trip; slow)."""
        buf = bytearray()
        for off in range(0, (size + 3) & ~3, 4):
            word = self.read_word(addr + off)
            buf += struct.pack("<I", word)
        return bytes(buf[:size])

    def write_range(self, addr: int, data: bytes) -> None:
        """Write aligned bytes via rw commands."""
        for off in range(0, len(data), 4):
            word = struct.unpack_from("<I", data.ljust(off + 4, b"\x00"), off)[0]
            self.write_word(addr + off, word)

    def upload_firmware(self, fw_data: bytes) -> None:
        """
        Firmware update via UART: ~<1 MB payload>~
        Payload padded/truncated to exactly 1 MB.
        """
        size = 1 << 20
        if len(fw_data) != size:
            warn(f"Firmware is {len(fw_data)} bytes; padding/truncating to {size}")
            fw_data = (fw_data + b"\xff" * size)[:size]
        info(f"Uploading {size // 1024} KB firmware via SAFE UART=")
        self._ser.write(b"~")
        self._ser.write(fw_data)
        self._ser.write(b"~")
        self._ser.flush()
        ok("Firmware upload sent")

    def interactive_shell(self):
        hdr("Samsung SAFE UART Shell  (rr <addr> | rw <addr> <val> | quit)")
        while True:
            try:
                line = input("safe> ").strip()
                if not line or line in ("quit", "q", "exit"):
                    break
                parts = line.split()
                if parts[0] == "rr" and len(parts) == 2:
                    self.read_word(int(parts[1], 16))
                elif parts[0] == "rw" and len(parts) == 3:
                    self.write_word(int(parts[1], 16), int(parts[2], 16))
                    ok(f"  wrote 0x{int(parts[2], 16):08X} -- 0x{int(parts[1], 16):08X}")
                else:
                    warn("Usage:  rr <addr>   |   rw <addr> <val>   (hex, no 0x prefix)")
            except (EOFError, KeyboardInterrupt):
                break

    def close(self):
        self._ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
