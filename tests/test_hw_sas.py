import struct

from hdd_toolkit.hw.sas import (
    SCSICapacity,
    SCSIInquiryData,
    SCSIOpcode,
    SESElementStatus,
    VPDPage,
    build_inquiry_cdb,
    build_mode_sense_10_cdb,
    build_read_capacity_10_cdb,
    build_read_capacity_16_cdb,
    build_receive_diagnostic_cdb,
    parse_ses_enclosure_status,
)


# =============================================================================
# CDB builders
# =============================================================================


def test_inquiry_cdb_opcode():
    cdb = build_inquiry_cdb()
    assert cdb[0] == SCSIOpcode.INQUIRY


def test_inquiry_cdb_length():
    cdb = build_inquiry_cdb()
    assert len(cdb) == 6


def test_inquiry_evpd_bit():
    cdb = build_inquiry_cdb(evpd=True, page_code=0x80)
    assert cdb[1] & 0x01 == 1


def test_inquiry_no_evpd_bit():
    cdb = build_inquiry_cdb(evpd=False)
    assert cdb[1] & 0x01 == 0


def test_inquiry_page_code_set():
    cdb = build_inquiry_cdb(evpd=True, page_code=0x83)
    assert cdb[2] == 0x83


def test_inquiry_alloc_len_encoded():
    cdb = build_inquiry_cdb(alloc_len=0x0200)
    alloc = (cdb[3] << 8) | cdb[4]
    assert alloc == 0x0200


def test_read_capacity_10_opcode():
    cdb = build_read_capacity_10_cdb()
    assert cdb[0] == SCSIOpcode.READ_CAPACITY_10


def test_read_capacity_10_length():
    cdb = build_read_capacity_10_cdb()
    assert len(cdb) == 10


def test_read_capacity_16_length():
    cdb = build_read_capacity_16_cdb()
    assert len(cdb) == 16


def test_read_capacity_16_opcode():
    cdb = build_read_capacity_16_cdb()
    assert cdb[0] == SCSIOpcode.SERVICE_ACTION_IN_16


def test_read_capacity_16_service_action():
    cdb = build_read_capacity_16_cdb()
    assert (cdb[1] & 0x1F) == 0x10


def test_receive_diagnostic_opcode():
    cdb = build_receive_diagnostic_cdb(page_code=0x02)
    assert cdb[0] == SCSIOpcode.RECEIVE_DIAGNOSTIC_RESULTS


def test_receive_diagnostic_page_code():
    cdb = build_receive_diagnostic_cdb(page_code=0x0A)
    assert cdb[2] == 0x0A


def test_mode_sense_10_opcode():
    cdb = build_mode_sense_10_cdb(page_code=0x08)
    assert cdb[0] == SCSIOpcode.MODE_SENSE_10


def test_mode_sense_10_page_code():
    cdb = build_mode_sense_10_cdb(page_code=0x08)
    assert (cdb[2] & 0x3F) == 0x08


# =============================================================================
# SCSIInquiryData.parse
# =============================================================================


def _make_inquiry_response(pdt=0x00, vendor=b"SEAGATE ", product=b"ST4000NM0025        ", rev=b"SN04"):
    buf = bytearray(96)
    buf[0] = pdt & 0x1F
    buf[2] = 0x07
    buf[8:16] = vendor[:8].ljust(8)
    buf[16:32] = product[:16].ljust(16)
    buf[32:36] = rev[:4].ljust(4)
    return bytes(buf)


def test_parse_vendor_id():
    data = _make_inquiry_response()
    inq = SCSIInquiryData.parse(data)
    assert "SEAGATE" in inq.vendor_id


def test_parse_product_id():
    data = _make_inquiry_response()
    inq = SCSIInquiryData.parse(data)
    assert "ST4000NM0025" in inq.product_id


def test_parse_product_rev():
    data = _make_inquiry_response()
    inq = SCSIInquiryData.parse(data)
    assert inq.product_rev == "SN04"


def test_parse_device_type():
    data = _make_inquiry_response(pdt=0x00)
    inq = SCSIInquiryData.parse(data)
    assert inq.peripheral_device_type == 0x00
    assert "SBC" in inq.device_type_name


def test_parse_ses_device_type():
    data = _make_inquiry_response(pdt=0x0D)
    inq = SCSIInquiryData.parse(data)
    assert "SES" in inq.device_type_name


def test_parse_spc_version():
    data = _make_inquiry_response()
    inq = SCSIInquiryData.parse(data)
    assert inq.spc_version == "SPC-5"


def test_parse_short_response_returns_defaults():
    inq = SCSIInquiryData.parse(bytes(10))
    assert inq.vendor_id == ""


# =============================================================================
# SCSICapacity
# =============================================================================


def test_parse_capacity_10():
    data = struct.pack(">II", 0x0EA9FFFF, 512)
    cap = SCSICapacity.parse_10(data)
    assert cap.last_lba == 0x0EA9FFFF
    assert cap.block_length == 512


def test_capacity_10_total_bytes():
    data = struct.pack(">II", 9, 512)
    cap = SCSICapacity.parse_10(data)
    assert cap.total_bytes == 10 * 512


def test_parse_capacity_16():
    buf = bytearray(32)
    struct.pack_into(">Q", buf, 0, 0x1_0000_0000)
    struct.pack_into(">I", buf, 8, 4096)
    cap = SCSICapacity.parse_16(bytes(buf))
    assert cap.last_lba == 0x1_0000_0000
    assert cap.block_length == 4096
    assert cap.is_16 is True


def test_capacity_10_total_gb_approximate():
    data = struct.pack(">II", 3_906_250_000, 512)
    cap = SCSICapacity.parse_10(data)
    assert cap.total_gb > 1_900


def test_capacity_short_returns_defaults():
    cap = SCSICapacity.parse_10(bytes(4))
    assert cap.last_lba == 0


# =============================================================================
# SES Enclosure Status parser
# =============================================================================


def _make_ses_status_page(element_bytes: list[bytes]) -> bytes:
    body = b"".join(element_bytes)
    page_len = 4 + len(body)
    header = bytes([0x02, 0x00]) + struct.pack(">H", page_len) + struct.pack(">I", 1)
    return header + body


def test_parse_ses_empty_page():
    buf = bytes(8)
    elements = parse_ses_enclosure_status(buf)
    assert elements == []


def test_parse_ses_one_ok_element():
    element = bytes([0x01, 0x00, 0x00, 0x00])
    buf = _make_ses_status_page([element])
    elements = parse_ses_enclosure_status(buf)
    assert len(elements) == 1
    assert elements[0].status_code == 0x01
    assert elements[0].status_name == "ok"


def test_parse_ses_critical_element():
    element = bytes([0x02, 0x00, 0x00, 0x00])
    buf = _make_ses_status_page([element])
    elements = parse_ses_enclosure_status(buf)
    assert elements[0].status_code == 0x02
    assert elements[0].status_name == "critical"


def test_parse_ses_disabled_element():
    element = bytes([0x20 | 0x01, 0x00, 0x00, 0x00])
    buf = _make_ses_status_page([element])
    elements = parse_ses_enclosure_status(buf)
    assert elements[0].disabled is True


def test_parse_ses_swap_bit():
    element = bytes([0x10 | 0x01, 0x00, 0x00, 0x00])
    buf = _make_ses_status_page([element])
    elements = parse_ses_enclosure_status(buf)
    assert elements[0].swap is True


def test_parse_ses_multiple_elements():
    elements_bytes = [
        bytes([0x01, 0x00, 0x00, 0x00]),
        bytes([0x02, 0x00, 0x00, 0x00]),
        bytes([0x05, 0x00, 0x00, 0x00]),
    ]
    buf = _make_ses_status_page(elements_bytes)
    result = parse_ses_enclosure_status(buf)
    assert len(result) == 3


def test_parse_ses_slot_numbering():
    elements_bytes = [bytes([0x01, 0, 0, 0])] * 4
    buf = _make_ses_status_page(elements_bytes)
    result = parse_ses_enclosure_status(buf)
    slots = [e.slot_number for e in result]
    assert slots == [0, 1, 2, 3]


# =============================================================================
# VPD page codes
# =============================================================================


def test_vpd_unit_serial_number():
    assert VPDPage.UNIT_SERIAL_NUMBER == 0x80


def test_vpd_device_identification():
    assert VPDPage.DEVICE_IDENTIFICATION == 0x83


def test_vpd_block_limits():
    assert VPDPage.BLOCK_LIMITS == 0xB0
