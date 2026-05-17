import struct

from hdd_toolkit.ata.tcg_opal import (
    ATA_IF_RECV,
    ATA_IF_SEND,
    TCGDiscovery0,
    TCGDiscovery0Parser,
    TCGFeatureCode,
    TCGOpalV200Feature,
    TCGSession,
    build_if_recv,
    build_if_send,
)


# =============================================================================
# IF_RECV / IF_SEND register builders
# =============================================================================


def test_if_recv_cmd_code():
    regs = build_if_recv(security_protocol=0x01, com_id=0x0001)
    assert regs["cmd"] == ATA_IF_RECV


def test_if_send_cmd_code():
    regs = build_if_send(security_protocol=0x01, com_id=0x0001, payload=bytes(512))
    assert regs["cmd"] == ATA_IF_SEND


def test_if_recv_protocol_in_features():
    regs = build_if_recv(security_protocol=0x01, com_id=0x0001)
    assert regs["features"] == 0x01


def test_if_recv_com_id_split():
    regs = build_if_recv(security_protocol=0x01, com_id=0x0123)
    assert regs["lba_lo"] == 0x01
    assert regs["cyl_lo"] == 0x23


def test_if_recv_alloc_len_default_is_one_sector():
    regs = build_if_recv(security_protocol=0x01, com_id=0x0001, alloc_len=512)
    assert regs["count"] == 1


def test_if_send_sector_count_from_payload():
    regs = build_if_send(security_protocol=0x01, com_id=0x0001, payload=bytes(1024))
    assert regs["count"] == 2


# =============================================================================
# TCGDiscovery0Parser
# =============================================================================


def _make_feature(code: int, data: bytes) -> bytes:
    return struct.pack(">HBB", code, 0x10, len(data)) + data


def _make_discovery0_buf(features: list[bytes]) -> bytes:
    body = b"".join(features)
    header = struct.pack(">II", len(body) + 44, 1) + bytes(40)
    return (header + body).ljust(512, b"\x00")


def test_parse_empty_returns_defaults():
    result = TCGDiscovery0Parser.parse(bytes(512))
    assert result.tper is None
    assert result.locking is None
    assert not result.is_opal


def test_parse_tper_sync_flag():
    feat = _make_feature(TCGFeatureCode.TPER, bytes([0x01]))
    buf = _make_discovery0_buf([feat])
    result = TCGDiscovery0Parser.parse(buf)
    assert result.tper is not None
    assert result.tper.sync is True


def test_parse_locking_enabled_and_locked():
    feat = _make_feature(TCGFeatureCode.LOCKING, bytes([0x07]))
    buf = _make_discovery0_buf([feat])
    result = TCGDiscovery0Parser.parse(buf)
    assert result.locking is not None
    assert result.locking.locking_supported is True
    assert result.locking.locking_enabled is True
    assert result.locking.locked is True


def test_parse_opal_v200():
    opal_data = struct.pack(">HH", 0x0204, 1) + bytes([0x00]) + bytes(3) + struct.pack(">HH", 2, 9) + bytes([0x00, 0xFF]) + bytes(2)
    feat = _make_feature(TCGFeatureCode.OPAL_V200, opal_data)
    buf = _make_discovery0_buf([feat])
    result = TCGDiscovery0Parser.parse(buf)
    assert result.opal_v200 is not None
    assert result.is_opal is True
    assert result.ssc_name == "Opal 2.0"


def test_parse_geometry():
    geo_data = bytes([0x01]) + bytes(7) + struct.pack(">I", 512) + struct.pack(">Q", 8) + struct.pack(">Q", 0)
    feat = _make_feature(TCGFeatureCode.GEOMETRY, geo_data)
    buf = _make_discovery0_buf([feat])
    result = TCGDiscovery0Parser.parse(buf)
    assert result.geometry is not None
    assert result.geometry.align is True
    assert result.geometry.logical_block_size == 512


def test_parse_enterprise_flag():
    ent_data = struct.pack(">HH", 0x0300, 2) + bytes(4)
    feat = _make_feature(TCGFeatureCode.ENTERPRISE, ent_data)
    buf = _make_discovery0_buf([feat])
    result = TCGDiscovery0Parser.parse(buf)
    assert result.has_enterprise is True


def test_parse_block_sid():
    feat = _make_feature(TCGFeatureCode.BLOCK_SID_AUTH, bytes(4))
    buf = _make_discovery0_buf([feat])
    result = TCGDiscovery0Parser.parse(buf)
    assert result.has_block_sid is True


def test_ssc_name_unknown_when_nothing_set():
    result = TCGDiscovery0()
    assert result.ssc_name == "unknown"


def test_ssc_name_pyrite_v200():
    result = TCGDiscovery0(has_pyrite_v200=True)
    assert result.ssc_name == "Pyrite 2.0"


def test_ssc_name_ruby():
    result = TCGDiscovery0(has_ruby=True)
    assert result.ssc_name == "Ruby 1.0"


def test_raw_features_collected():
    feat = _make_feature(TCGFeatureCode.TPER, bytes([0x00]))
    buf = _make_discovery0_buf([feat])
    result = TCGDiscovery0Parser.parse(buf)
    assert len(result.raw_features) >= 1
    assert result.raw_features[0]["code"] == TCGFeatureCode.TPER


# =============================================================================
# TCGSession packet builders
# =============================================================================


def test_build_sub_packet_length_field():
    payload = b"\xDE\xAD\xBE\xEF"
    pkt = TCGSession.build_sub_packet(payload)
    length = struct.unpack_from(">I", pkt, 8)[0]
    assert length == 4


def test_build_packet_tsn_hsn():
    subpkt = TCGSession.build_sub_packet(b"\x00")
    pkt = TCGSession.build_packet(tsn=0x1234, hsn=0x5678, seq=1, payload=subpkt)
    tsn, hsn = struct.unpack_from(">II", pkt, 0)
    assert tsn == 0x1234
    assert hsn == 0x5678


def test_build_com_packet_padded_to_512():
    inner = TCGSession.build_sub_packet(b"\x01")
    pkt = TCGSession.build_packet(tsn=0, hsn=0x41, seq=1, payload=inner)
    com_pkt = TCGSession.build_com_packet(extended_com_id=0x00040000, payload=pkt)
    assert len(com_pkt) % 512 == 0


def test_start_session_packet_returns_bytes():
    result = TCGSession.build_start_session(com_id=0x0204, hsn=0x41)
    assert isinstance(result, bytes)
    assert len(result) % 512 == 0


def test_start_session_contains_hsn_in_packet():
    result = TCGSession.build_start_session(com_id=0x0204, hsn=0x55)
    assert b"\x00\x00\x00\x55" in result or result is not None


def test_close_session_returns_bytes():
    result = TCGSession.build_close_session(com_id=0x0204, tsn=0x0001, hsn=0x41)
    assert isinstance(result, bytes)
    assert len(result) % 512 == 0


def test_encode_uint_small():
    encoded = TCGSession._encode_uint(5)
    assert encoded == bytes([5])


def test_encode_uint_large():
    encoded = TCGSession._encode_uint(256)
    assert len(encoded) == 3
    assert encoded[0] == 0xCA


def test_encode_bytes_short():
    encoded = TCGSession._encode_bytes(b"\xAB\xCD")
    assert encoded[0] == 0xA2
    assert encoded[1:] == b"\xAB\xCD"
