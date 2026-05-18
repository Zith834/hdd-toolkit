from hdd_toolkit.ata.seagate_f3_terminal import (
    F3_BAUD_LEGACY,
    F3_BAUD_MODERN,
    F3_CTRL_Z,
    F3Level,
    F3SAReadCmd,
    F3TerminalResponse,
    SeagateF3ROMMap,
    SeagateF3Terminal,
    build_sa_sector_descriptor,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_ctrl_z_value():
    assert F3_CTRL_Z == b"\x1a"


def test_baud_legacy():
    assert F3_BAUD_LEGACY == 38400


def test_baud_modern():
    assert F3_BAUD_MODERN == 115200


def test_level_enum_values():
    assert F3Level.LEVEL_0 == 0
    assert F3Level.LEVEL_1 == 1
    assert F3Level.LEVEL_T == ord("T")


# ---------------------------------------------------------------------------
# SeagateF3Terminal static command builders
# ---------------------------------------------------------------------------


def test_enter_level1_returns_ctrl_z():
    assert SeagateF3Terminal.enter_level1() == b"\x1a"


def test_spin_up_command():
    assert SeagateF3Terminal.spin_up() == "U"


def test_spin_down_command():
    assert SeagateF3Terminal.spin_down() == "Z"


def test_soft_reset_command():
    assert SeagateF3Terminal.soft_reset() == "R"


def test_print_identity_command():
    assert SeagateF3Terminal.print_identity() == "Q"


def test_print_p_list_command():
    assert SeagateF3Terminal.print_p_list() == "P"


def test_print_g_list_command():
    assert SeagateF3Terminal.print_g_list() == "G"


def test_clear_g_list_command():
    assert SeagateF3Terminal.clear_g_list() == "C6"


def test_toggle_sata_command():
    assert SeagateF3Terminal.build_toggle_sata() == "/1"


def test_enter_terminal_mode_command():
    assert SeagateF3Terminal.build_enter_terminal_mode() == "/T"


# ---------------------------------------------------------------------------
# set_active_heads
# ---------------------------------------------------------------------------


def test_set_active_heads_all():
    cmd = SeagateF3Terminal.set_active_heads(2, 0xFF)
    assert cmd == "N2,255"


def test_set_active_heads_one_head():
    cmd = SeagateF3Terminal.set_active_heads(1, 0x01)
    assert cmd == "N1,1"


def test_set_active_heads_mask_truncated():
    cmd = SeagateF3Terminal.set_active_heads(4, 0x1FF)
    assert "255" in cmd


# ---------------------------------------------------------------------------
# build_sa_read / build_sa_write
# ---------------------------------------------------------------------------


def test_build_sa_read_type():
    cmd = SeagateF3Terminal.build_sa_read(module_id=0x22)
    assert cmd.cmd_type == 4


def test_build_sa_read_module_id():
    cmd = SeagateF3Terminal.build_sa_read(module_id=0x34)
    assert cmd.module_id == 0x34


def test_build_sa_read_default_track():
    cmd = SeagateF3Terminal.build_sa_read(module_id=0x22)
    assert cmd.track == 1


def test_build_sa_read_custom_track():
    cmd = SeagateF3Terminal.build_sa_read(module_id=0x1D, track=2)
    assert cmd.track == 2


def test_build_sa_write_type():
    cmd = SeagateF3Terminal.build_sa_write(module_id=0x1E)
    assert cmd.cmd_type == 5


# ---------------------------------------------------------------------------
# F3SAReadCmd.encode
# ---------------------------------------------------------------------------


def test_f3_sa_read_encode_basic():
    cmd = F3SAReadCmd(cmd_type=4, track=1, module_id=0x22)
    encoded = cmd.encode()
    assert encoded == "i4,1,34"


def test_f3_sa_read_encode_with_offset():
    cmd = F3SAReadCmd(cmd_type=4, track=1, module_id=0x22, offset=0, length=512, flags=0)
    encoded = cmd.encode()
    assert encoded.startswith("i4,1,34,")
    assert "512" in encoded


def test_f3_sa_write_encode():
    cmd = F3SAReadCmd(cmd_type=5, track=1, module_id=0x1D)
    encoded = cmd.encode()
    assert encoded == "i5,1,29"


def test_build_sa_read_encode_roundtrip():
    cmd = SeagateF3Terminal.build_sa_read(module_id=0x1D, track=1)
    encoded = cmd.encode()
    assert "i4" in encoded
    assert "29" in encoded


# ---------------------------------------------------------------------------
# build_format_sa
# ---------------------------------------------------------------------------


def test_build_format_sa_default():
    cmd = SeagateF3Terminal.build_format_sa()
    assert cmd.startswith("m0,0,2,2")


def test_build_format_sa_custom():
    cmd = SeagateF3Terminal.build_format_sa(track=1, surface=3, step=4)
    assert "1" in cmd
    assert "3" in cmd
    assert "4" in cmd


# ---------------------------------------------------------------------------
# parse_response
# ---------------------------------------------------------------------------


def test_parse_response_success():
    result = SeagateF3Terminal.parse_response("OK\nF3 1>")
    assert result.success is True
    assert result.error_code == 0


def test_parse_response_error():
    result = SeagateF3Terminal.parse_response("ERR 0002\n")
    assert result.success is False
    assert result.error_code == 2


def test_parse_response_error_with_command():
    result = SeagateF3Terminal.parse_response("ERR 00FF\n", command="i4,1,22")
    assert result.command == "i4,1,22"
    assert result.error_code == 0xFF


def test_parse_response_preserves_raw():
    raw = "Some data\nERR 0001\n"
    result = SeagateF3Terminal.parse_response(raw)
    assert result.raw == raw


def test_parse_response_unknown_non_error():
    result = SeagateF3Terminal.parse_response("Model: ST4000DM004\n")
    assert result.success is True


# ---------------------------------------------------------------------------
# parse_identity
# ---------------------------------------------------------------------------


def test_parse_identity_model():
    raw = "Model: ST4000DM004-2CV104\nS/N: WS12ABCDEF01\nFW: CC54\n"
    info = SeagateF3Terminal.parse_identity(raw)
    assert info.model == "ST4000DM004-2CV104"


def test_parse_identity_serial():
    raw = "Model: ST4000DM004\nS/N: WS12ABCDEF01\nFW: 0001\n"
    info = SeagateF3Terminal.parse_identity(raw)
    assert info.serial == "WS12ABCDEF01"


def test_parse_identity_firmware():
    raw = "Model: ST4000DM004\nS/N: WS12AB\nFW: CC54\n"
    info = SeagateF3Terminal.parse_identity(raw)
    assert info.firmware == "CC54"


def test_parse_identity_empty_raw():
    info = SeagateF3Terminal.parse_identity("")
    assert info.model == ""
    assert info.serial == ""


def test_parse_identity_raw_lines():
    raw = "Model: ST4000DM004\nS/N: ABC\n"
    info = SeagateF3Terminal.parse_identity(raw)
    assert len(info.raw_lines) == 2


def test_parse_identity_cylinders():
    raw = "Cyl: 775156  Hds: 2  Spt: 63\n"
    info = SeagateF3Terminal.parse_identity(raw)
    assert info.cylinders == 775156


# ---------------------------------------------------------------------------
# SeagateF3ROMMap
# ---------------------------------------------------------------------------


def test_rommap_known_module():
    name = SeagateF3ROMMap.describe(0x03)
    assert name == "ROM_RESIDENT_0"


def test_rommap_congen():
    name = SeagateF3ROMMap.describe(0x34)
    assert name == "CONGEN_XML"


def test_rommap_g_list():
    name = SeagateF3ROMMap.describe(0x51)
    assert name == "G_LIST"


def test_rommap_unknown():
    name = SeagateF3ROMMap.describe(0xFF)
    assert "UNKNOWN" in name


def test_rommap_barracuda_7200_14_not_empty():
    assert len(SeagateF3ROMMap.BARRACUDA_7200_14) > 0


# ---------------------------------------------------------------------------
# build_sa_sector_descriptor
# ---------------------------------------------------------------------------


def test_build_sa_sector_descriptor_length():
    buf = build_sa_sector_descriptor(module_id=0x1D, op=0x01)
    assert len(buf) == 512


def test_build_sa_sector_descriptor_op():
    buf = build_sa_sector_descriptor(module_id=0x22, op=0x02)
    assert buf[0] == 0x02


def test_build_sa_sector_descriptor_module_id():
    buf = build_sa_sector_descriptor(module_id=0x34, op=0x01)
    assert buf[1] == 0x34


def test_build_sa_sector_descriptor_length_field():
    import struct

    buf = build_sa_sector_descriptor(module_id=0x0B, op=0x01, length=8)
    length = struct.unpack_from("<H", buf, 2)[0]
    assert length == 8


def test_build_sa_sector_descriptor_default_op():
    buf = build_sa_sector_descriptor(module_id=0x03)
    assert buf[0] == 0x01
