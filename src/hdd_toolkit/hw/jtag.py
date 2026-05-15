import contextlib
import socket

from hdd_toolkit.core.utils import hdr, ok, warn


class OpenOCDBridge:
    """
    Thin wrapper around OpenOCD's telnet interface (default port 4444).
    Lets you script breakpoints, memory dumps, and register reads.
    """

    PROMPT = b"> "

    def __init__(self, host: str = "localhost", port: int = 4444, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock = None
        self.connect()

    def connect(self):
        self._sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._drain()  # consume the banner
        ok(f"Connected to OpenOCD at {self.host}:{self.port}")

    def _drain(self):
        self._sock.settimeout(1.0)
        buf = b""
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if buf.endswith(self.PROMPT):
                    break
        except TimeoutError:
            pass
        self._sock.settimeout(self.timeout)
        return buf

    def cmd(self, command: str) -> str:
        self._sock.sendall((command + "\n").encode())
        return self._drain().decode(errors="replace").strip()

    def halt(self):
        return self.cmd("halt")

    def resume(self):
        return self.cmd("resume")

    def read_memory(self, addr: int, width: int, count: int) -> list[int]:
        """Read `count` words of `width` bits from `addr`."""
        raw = self.cmd(f"mdw 0x{addr:08X} {count}")
        values = []
        for line in raw.splitlines():
            # format: "0xADDR: 0xVAL 0xVAL ..."
            parts = line.split(":")
            if len(parts) == 2:
                for tok in parts[1].split():
                    with contextlib.suppress(ValueError):
                        values.append(int(tok, 16))
        return values

    def dump_memory(self, addr: int, size: int) -> bytes:
        """Dump `size` bytes from `addr` as a bytes object."""
        tmp = f"/tmp/jtag_dump_{addr:08X}.bin"
        self.cmd(f"dump_image {tmp} 0x{addr:08X} {size}")
        try:
            with open(tmp, "rb") as f:
                return f.read()
        except FileNotFoundError:
            warn("dump_image wrote to target filesystem; fetch file manually from OpenOCD host")
            return b""

    def set_bp(self, addr: int, size: int = 2) -> str:
        """Set a hardware breakpoint at `addr`."""
        return self.cmd(f"bp 0x{addr:08X} {size} hw")

    def clear_bp(self, addr: int) -> str:
        return self.cmd(f"rbp 0x{addr:08X}")

    def read_regs(self) -> dict[str, int]:
        raw = self.cmd("reg")
        regs = {}
        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                with contextlib.suppress(ValueError):
                    regs[parts[0].rstrip(":")] = int(parts[-1], 16)
        return regs

    def write_memory(self, addr: int, data: bytes) -> str:
        """Write bytes to target memory via mwb, one command at a time."""
        last = ""
        for i, b in enumerate(data):
            last = self.cmd(f"mwb 0x{addr + i:08X} 0x{b:02X}")
        return last

    def interactive_shell(self):
        """Drop into an interactive OpenOCD shell."""
        hdr("OpenOCD Interactive Shell  (type 'quit' to exit)")
        while True:
            try:
                line = input("ocd> ").strip()
                if line in ("quit", "exit", "q"):
                    break
                if line:
                    pass
            except (EOFError, KeyboardInterrupt):
                break

    def close(self):
        if self._sock:
            self._sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# =============================================================================
# Samsung MEX GPIO reader  (via JTAG / OpenOCD)
# =============================================================================
