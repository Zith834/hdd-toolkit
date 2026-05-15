import ctypes
import struct

from hdd_firmware_toolkit.core.utils import _hex_dump
from hdd_firmware_toolkit.nvme.admin import NVMeAdminPassthrough, NVMeDevice, NvmePassthruCmd


def test_nvme_passthru_cmd_struct_size():
    assert ctypes.sizeof(NvmePassthruCmd) == 72


def test_nvme_passthru_cmd_fields():
    cmd = NvmePassthruCmd()
    cmd.opcode = 0x06
    cmd.nsid = 1
    cmd.cdw10 = 0x01
    cmd.data_len = 4096
    cmd.timeout_ms = 5000
    assert cmd.opcode == 0x06
    assert cmd.nsid == 1
    assert cmd.cdw10 == 0x01
    assert cmd.data_len == 4096
    assert cmd.timeout_ms == 5000


def test_nvme_passthru_cmd_pack():
    cmd = NvmePassthruCmd()
    cmd.opcode = 0x02
    cmd.nsid = 0xFFFFFFFF
    cmd.cdw10 = 0x7F001F
    cmd.cdw11 = 0
    cmd.data_len = 512
    buf = (ctypes.c_uint8 * ctypes.sizeof(cmd))()
    ctypes.memmove(buf, ctypes.addressof(cmd), ctypes.sizeof(cmd))
    assert buf[0] == 0x02
    assert struct.unpack_from("<I", bytearray(buf), 4)[0] == 0xFFFFFFFF
    assert struct.unpack_from("<I", bytearray(buf), 40)[0] == 0x7F001F


def test_nvme_device_init():
    dev = NVMeDevice(0)
    assert dev._path == "/dev/nvme0"
    dev2 = NVMeDevice("/dev/nvme1")
    assert dev2._path == "/dev/nvme1"


def test_hex_dump_basic():
    data = bytes(range(32))
    result = _hex_dump(data, width=16)
    lines = result.split("\n")
    assert len(lines) == 2
    assert lines[0].startswith("00000000")
    assert "00 01 02 03" in lines[0]


def test_hex_dump_empty():
    assert _hex_dump(b"") == ""


def test_hex_dump_ascii():
    data = b"Hello World! Test 123"
    result = _hex_dump(data, width=16)
    assert "Hello" in result


def test_execute_admin_cmd_raises_no_device():
    cmd = NVMeAdminPassthrough.identify_ctrlr()
    try:
        NVMeAdminPassthrough.execute_admin_cmd(999, cmd)
        assert False, "Should have raised OSError"
    except OSError:
        pass


def test_execute_admin_cmd_raises_bad_path():
    cmd = NVMeAdminPassthrough.get_smart_log()
    try:
        NVMeAdminPassthrough.execute_admin_cmd("/dev/nvme-nonexistent", cmd)
        assert False, "Should have raised OSError"
    except OSError:
        pass


def test_nvme_device_context_manager_errors():

    dev = NVMeDevice(0)
    assert dev._fd is None
    try:
        dev.fileno
        assert False, "Should have raised RuntimeError"
    except RuntimeError:
        pass
    try:
        dev.send(NVMeAdminPassthrough.identify_ctrlr())
        assert False, "Should have raised RuntimeError"
    except RuntimeError:
        pass


def test_nvme_live_identify_cli():
    from hdd_firmware_toolkit.cli.handlers import build_parser

    parser = build_parser()
    args = parser.parse_args(["nvme-live-identify", "0"])
    assert args.device == "0"
    assert callable(args.func)


def test_nvme_live_smart_cli():
    from hdd_firmware_toolkit.cli.handlers import build_parser

    parser = build_parser()
    args = parser.parse_args(["nvme-live-smart", "0"])
    assert args.device == "0"
    assert callable(args.func)


def test_nvme_live_get_log_cli():
    from hdd_firmware_toolkit.cli.handlers import build_parser

    parser = build_parser()
    args = parser.parse_args(["nvme-live-get-log", "0xC0", "--device", "0"])
    assert args.log_id == 0xC0
    assert args.device == "0"
    assert callable(args.func)


def test_nvme_live_fw_log_cli():
    from hdd_firmware_toolkit.cli.handlers import build_parser

    parser = build_parser()
    args = parser.parse_args(["nvme-live-fw-log", "0"])
    assert args.device == "0"
    assert callable(args.func)


def test_nvme_live_send_cli():
    from hdd_firmware_toolkit.cli.handlers import build_parser

    parser = build_parser()
    args = parser.parse_args(["nvme-live-send", "0xC0", "--device", "0"])
    assert args.opcode == 0xC0
    assert args.device == "0"
    assert callable(args.func)


def test_sandisk_live_sniff_cli():
    from hdd_firmware_toolkit.cli.handlers import build_parser

    parser = build_parser()
    args = parser.parse_args(["sandisk-live-sniff", "0"])
    assert args.device == "0"
    assert callable(args.func)


def test_nvme_live_identify_hex_flag():
    from hdd_firmware_toolkit.cli.handlers import build_parser

    parser = build_parser()
    args = parser.parse_args(["nvme-live-identify", "0", "--hex"])
    assert args.hex is True


def test_nvme_live_send_with_file():
    import tempfile

    from hdd_firmware_toolkit.cli.handlers import build_parser

    with tempfile.NamedTemporaryFile() as f:
        f.write(b"test firmware data")
        f.flush()
        parser = build_parser()
        args = parser.parse_args([
            "nvme-live-send", "0x11", "--device", "0",
            "--cdw10", "0x100", "--file", f.name,
        ])
        assert args.opcode == 0x11
        assert args.file == f.name
