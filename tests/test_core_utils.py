from hdd_toolkit.core.utils import _c, diff_firmware, hexdump, scan_strings


def test_c_no_tty():
    result = _c("32", "hello")
    assert result == "hello"


def test_hexdump_basic():
    data = bytes(range(256))
    dump = hexdump(data, addr=0, width=16)
    assert "00000000" in dump
    assert "ff" in dump.lower()


def test_hexdump_empty():
    dump = hexdump(b"")
    assert dump == ""


def test_scan_strings_empty():
    data = bytes(range(256))
    strings = scan_strings(data, min_len=5)
    assert len(strings) >= 0


def test_scan_strings_finds_ascii():
    data = b"hello world\x00\x00\x00test string\x00"
    strings = scan_strings(data, min_len=3)
    found = [s for _, s in strings]
    assert "hello world" in found
    assert "test string" in found


def test_diff_firmware_identical():
    data = b"\x00\x01\x02\x03"
    diffs = diff_firmware(data, data)
    assert diffs == []


def test_diff_firmware_different():
    a = b"\x00\x01\x02\x03"
    b = b"\x00\xFF\x02\xFF"
    diffs = diff_firmware(a, b)
    assert len(diffs) == 2
    assert diffs[0] == (1, b"\x01", b"\xFF")
    assert diffs[1] == (3, b"\x03", b"\xFF")
