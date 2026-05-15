from unittest.mock import MagicMock, patch

from hdd_firmware_toolkit.hw.jtag import OpenOCDBridge


@patch("socket.create_connection")
def test_openocd_init(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.return_value = b""
    bridge = OpenOCDBridge(host="localhost", port=4444, timeout=1)
    assert bridge.host == "localhost"
    assert bridge.port == 4444


@patch("socket.create_connection")
def test_openocd_cmd(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.return_value = b""
    bridge = OpenOCDBridge(host="localhost", port=4444, timeout=1)
    bridge._drain()
    bridge.cmd("halt")
    mock_sock.sendall.assert_called_once_with(b"halt\n")


@patch("socket.create_connection")
def test_openocd_read_memory(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.return_value = b""
    bridge = OpenOCDBridge(host="localhost", port=4444, timeout=1)
    bridge._drain()
    result = bridge.read_memory(0x2000, 32, 4)
    assert result == []


@patch("socket.create_connection")
def test_openocd_dump_memory(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.return_value = b""
    bridge = OpenOCDBridge(host="localhost", port=4444, timeout=1)
    bridge._drain()
    data = bridge.dump_memory(0x2000, 100)
    assert data == b""


@patch("socket.create_connection")
def test_openocd_read_regs(mock_conn):
    mock_sock = MagicMock()
    mock_conn.return_value = mock_sock
    mock_sock.recv.return_value = b""
    bridge = OpenOCDBridge(host="localhost", port=4444, timeout=1)
    bridge._drain()
    regs = bridge.read_regs()
    assert regs == {}
