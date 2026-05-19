from hdd_toolkit.hw.serial_console import DriveSerialConsole, GdbStub, MaskRomBootMenu


class MockSerial:
    def __init__(self, reads: bytes = b""):
        self.writes: list[bytes] = []
        self._reads = bytearray(reads)

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        return None

    def read(self, n: int = 1) -> bytes:
        if not self._reads:
            return b""
        out = bytes(self._reads[:n])
        del self._reads[:n]
        return out

    def readline(self) -> bytes:
        return b""

    def close(self) -> None:
        return None


def test_rsp_checksum():
    assert GdbStub._rsp_checksum(b"g") == b"67"


def test_send_packet_format():
    console = DriveSerialConsole(port="mock")
    console._ser = MockSerial(reads=b"+")
    stub = GdbStub(console=console, stub_addr=0x1000)

    stub._send_packet(b"g")

    assert console._ser.writes[0] == b"$g#67"


def test_stub_is_stateless():
    assert GdbStub.STUB_IS_STATELESS is True


def test_stub_size():
    assert MaskRomBootMenu.STUB_SIZE_BYTES == 3482


def test_boot_menu_break_sequence():
    assert MaskRomBootMenu.BOOT_MENU_BREAK == b"\x08"


def test_console_prompt():
    assert DriveSerialConsole.PROMPT == "F3 T>"


def test_dump_memory_parses_hex():
    console = DriveSerialConsole(port="mock")
    console.send_command = lambda _cmd: "00 11 22 33 44"
    assert console.dump_memory(0, 4) == b"\x00\x11\x22\x33"


def test_write_memory_sends_commands():
    sent: list[str] = []
    console = DriveSerialConsole(port="mock")

    def fake_send(cmd: str) -> str:
        sent.append(cmd)
        return "OK"

    console.send_command = fake_send
    assert console.write_memory(0x1000, b"\xde\xad") is True
    assert sent == ["mw 0x00001000 0xDE", "mw 0x00001001 0xAD"]
