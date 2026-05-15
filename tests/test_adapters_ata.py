from hdd_firmware_toolkit.ata.sat import SATLayer


def test_build_ata_pass_through_16_pio():
    cdb = SATLayer.build_ata_pass_through_16(
        ata_cmd=0x25, lba=0x100, sector_count=1, protocol=4
    )
    assert len(cdb) == 16
    assert cdb[0] == 0x85
    assert cdb[1] & 0x1F == 4
    assert cdb[8] == 0x25


def test_build_ata_pass_through_12():
    cdb = SATLayer.build_ata_pass_through_12(ata_cmd=0x25, lba=0x100)
    assert len(cdb) == 12
    assert cdb[0] == 0xA1


def test_build_ata_pass_through_32():
    cdb = SATLayer.build_ata_pass_through_32(ata_cmd=0x25, lba=0x100)
    assert len(cdb) == 32
    assert cdb[0] == 0x7F


def test_build_read_16():
    cdb = SATLayer.build_read_16(lba=0x100, sector_count=1)
    assert cdb[0] == 0x88


def test_build_write_16():
    cdb = SATLayer.build_write_16(lba=0x100, sector_count=1)
    assert cdb[0] == 0x8A


def test_build_inquiry():
    cdb = SATLayer.build_inquiry(evpd=False, page_code=0)
    assert len(cdb) == 6
    assert cdb[0] == 0x12


def test_build_read_capacity_16():
    cdb = SATLayer.build_read_capacity_16()
    assert cdb[0] == 0x9E


def test_parse_ata_return_descriptor():
    data = bytearray(16)
    data[0] = 0x09
    data[2] = 0x50
    data[3] = 0x02
    data[6] = 0x01
    data[8:14] = 0x123456789ABC.to_bytes(6, "little")
    result = SATLayer.parse_ata_return_descriptor(bytes(data))
    assert isinstance(result, dict)


def test_ata_status_to_sense():
    sense = SATLayer.ata_status_to_sense(0x50, 0)
    assert len(sense) >= 18
    assert sense[0] == 0x72


def test_ata_status_to_sense_error():
    sense = SATLayer.ata_status_to_sense(0x51, 0x04)
    assert len(sense) >= 18
