import struct

from hdd_toolkit.nvme.hmb import (
    NVME_FID_HOST_MEMORY_BUFFER,
    NVME_GET_FEATURES_OPCODE,
    NVME_SET_FEATURES_OPCODE,
    HMBAllocation,
    HMBAttackModel,
    HMBDescriptor,
    build_hmb_disable_cmd,
    build_hmb_enable_cmd,
    build_hmb_get_cmd,
    parse_hmb_caps_from_identify,
)


# =============================================================================
# HMBDescriptor
# =============================================================================


def test_descriptor_size_bytes():
    d = HMBDescriptor(base_address=0x1000, size_4k=4)
    assert d.size_bytes == 4 * 4096


def test_descriptor_pack_length():
    d = HMBDescriptor(base_address=0x10000, size_4k=1)
    assert len(d.pack()) == 16


def test_descriptor_pack_base_address():
    d = HMBDescriptor(base_address=0xDEAD_0000, size_4k=2)
    packed = d.pack()
    base = struct.unpack_from("<Q", packed, 0)[0]
    assert base == 0xDEAD_0000


def test_descriptor_pack_size():
    d = HMBDescriptor(base_address=0, size_4k=8)
    packed = d.pack()
    size = struct.unpack_from("<I", packed, 8)[0]
    assert size == 8


def test_descriptor_roundtrip():
    d = HMBDescriptor(base_address=0xCAFE_F000, size_4k=16)
    d2 = HMBDescriptor.unpack(d.pack())
    assert d2.base_address == d.base_address
    assert d2.size_4k == d.size_4k


def test_descriptor_unpack_short_returns_defaults():
    d = HMBDescriptor.unpack(bytes(4))
    assert d.base_address == 0


# =============================================================================
# HMBAllocation
# =============================================================================


def test_allocation_total_size():
    alloc = HMBAllocation(descriptors=[
        HMBDescriptor(base_address=0x1000, size_4k=4),
        HMBDescriptor(base_address=0x5000, size_4k=4),
    ])
    assert alloc.total_size_bytes == 8 * 4096


def test_allocation_descriptor_count():
    alloc = HMBAllocation(descriptors=[HMBDescriptor()] * 3)
    assert alloc.descriptor_count == 3


def test_allocation_pack_list_length():
    alloc = HMBAllocation(descriptors=[HMBDescriptor()] * 3)
    assert len(alloc.pack_descriptor_list()) == 3 * 16


def test_allocation_from_descriptor_list_roundtrip():
    alloc = HMBAllocation(descriptors=[
        HMBDescriptor(base_address=0x1000, size_4k=2),
        HMBDescriptor(base_address=0x9000, size_4k=4),
    ])
    raw = alloc.pack_descriptor_list()
    restored = HMBAllocation.from_descriptor_list(raw)
    assert restored.descriptor_count == 2
    assert restored.descriptors[0].base_address == 0x1000
    assert restored.descriptors[1].size_4k == 4


# =============================================================================
# Admin command builders
# =============================================================================


def test_hmb_enable_opcode():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=4)])
    cmd = build_hmb_enable_cmd(alloc, descriptor_list_addr=0x1000)
    assert cmd.opcode == NVME_SET_FEATURES_OPCODE


def test_hmb_enable_fid():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=4)])
    cmd = build_hmb_enable_cmd(alloc, descriptor_list_addr=0x1000)
    assert cmd.cdw10 == NVME_FID_HOST_MEMORY_BUFFER


def test_hmb_enable_ehm_bit():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=4)])
    cmd = build_hmb_enable_cmd(alloc, descriptor_list_addr=0x1000)
    assert cmd.cdw11 & 0x01 == 1


def test_hmb_enable_mr_bit():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=4)])
    cmd = build_hmb_enable_cmd(alloc, descriptor_list_addr=0x1000, mr=True)
    assert cmd.cdw11 & 0x02 == 2


def test_hmb_enable_hsize():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=8)])
    cmd = build_hmb_enable_cmd(alloc, descriptor_list_addr=0x1000)
    assert cmd.cdw12 == 8


def test_hmb_enable_descriptor_list_addr_split():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=1)])
    addr = 0x0000_0001_8000_0000
    cmd = build_hmb_enable_cmd(alloc, descriptor_list_addr=addr)
    assert cmd.cdw13 == 0x8000_0000
    assert cmd.cdw14 == 0x0000_0001


def test_hmb_disable_opcode():
    cmd = build_hmb_disable_cmd()
    assert cmd.opcode == NVME_SET_FEATURES_OPCODE


def test_hmb_disable_ehm_clear():
    cmd = build_hmb_disable_cmd()
    assert cmd.cdw11 & 0x01 == 0


def test_hmb_get_opcode():
    cmd = build_hmb_get_cmd()
    assert cmd.opcode == NVME_GET_FEATURES_OPCODE


def test_hmb_get_fid():
    cmd = build_hmb_get_cmd()
    assert cmd.cdw10 == NVME_FID_HOST_MEMORY_BUFFER


# =============================================================================
# parse_hmb_caps_from_identify
# =============================================================================


def _make_identify(hmmin: int = 0, hmpre: int = 0) -> bytes:
    buf = bytearray(4096)
    struct.pack_into("<I", buf, 272, hmmin)
    struct.pack_into("<Q", buf, 276, hmpre)
    return bytes(buf)


def test_hmb_caps_supported():
    data = _make_identify(hmmin=64, hmpre=256)
    caps = parse_hmb_caps_from_identify(data)
    assert caps["hmb_supported"] is True


def test_hmb_caps_not_supported_when_hmmin_zero():
    data = _make_identify(hmmin=0)
    caps = parse_hmb_caps_from_identify(data)
    assert caps["hmb_supported"] is False


def test_hmb_caps_hmmin_bytes():
    data = _make_identify(hmmin=16)
    caps = parse_hmb_caps_from_identify(data)
    assert caps["hmmin_bytes"] == 16 * 4096


def test_hmb_caps_hmpre_bytes():
    data = _make_identify(hmmin=16, hmpre=64)
    caps = parse_hmb_caps_from_identify(data)
    assert caps["hmpre_bytes"] == 64 * 4096


def test_hmb_caps_short_identify():
    caps = parse_hmb_caps_from_identify(bytes(100))
    assert caps["hmb_supported"] is False


# =============================================================================
# HMBAttackModel
# =============================================================================


def test_attack_model_enumerate_regions():
    alloc = HMBAllocation(descriptors=[
        HMBDescriptor(base_address=0x1000, size_4k=4),
        HMBDescriptor(base_address=0x5000, size_4k=2),
    ])
    model = HMBAttackModel(alloc)
    regions = model.enumerate_regions()
    assert len(regions) == 2
    assert regions[0]["base_address"] == 0x1000
    assert regions[0]["size_bytes"] == 4 * 4096


def test_attack_model_overflow_model():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=4)])
    model = HMBAttackModel(alloc)
    overflow = model.estimate_overflow_range(overflow_pages=2)
    assert len(overflow) == 1
    assert overflow[0]["overflow_bytes"] == 2 * 4096
    expected_start = 0x1000 + 4 * 4096
    assert overflow[0]["overflow_start"] == expected_start


def test_attack_report_total_size():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x10000, size_4k=16)])
    model = HMBAttackModel(alloc)
    report = model.attack_report()
    assert report["total_size_bytes"] == 16 * 4096


def test_attack_report_large_hmb_flag():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x10000, size_4k=16384)])
    model = HMBAttackModel(alloc)
    report = model.attack_report()
    assert "large_hmb_over_64mb" in report["risk_flags"]


def test_attack_report_low_memory_flag():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=1)])
    model = HMBAttackModel(alloc)
    report = model.attack_report()
    assert "low_memory_region_below_1mb" in report["risk_flags"]


def test_attack_report_risk_level_high_when_flags():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x1000, size_4k=1)])
    model = HMBAttackModel(alloc)
    report = model.attack_report()
    assert report["risk_level"] == "high"


def test_attack_report_risk_level_medium_clean():
    alloc = HMBAllocation(descriptors=[HMBDescriptor(base_address=0x10_0000, size_4k=8)])
    model = HMBAttackModel(alloc)
    report = model.attack_report()
    assert report["risk_level"] == "medium"
