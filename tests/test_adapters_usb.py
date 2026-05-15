from hdd_toolkit.hw.usb_bridge import USBToSATABridge


def test_identify_from_inquiry_jmicron():
    info = USBToSATABridge.identify_from_inquiry("JMicron", "Generic")
    assert info is not None
    assert info.chip_name == "JMS539"


def test_identify_from_inquiry_asmedia():
    info = USBToSATABridge.identify_from_inquiry("ASMT", "ASM1153")
    assert info is not None
    assert "ASM" in info.chip_name or info.vendor_id == 0


def test_identify_from_inquiry_unknown():
    info = USBToSATABridge.identify_from_inquiry("Unknown", "Vendor")
    assert info is not None
    assert info.chip_name == "Unknown"


def test_identify_from_vid_pid_jmicron():
    info = USBToSATABridge.identify_from_vid_pid(0x152D, 0x0539)
    assert info is not None
    assert info.chip_name == "JMS539"


def test_identify_from_vid_pid_asmedia():
    info = USBToSATABridge.identify_from_vid_pid(0x174C, 0x2362)
    assert info is not None
    assert info.chip_name == "ASM2362"


def test_identify_from_vid_pid_unknown():
    info = USBToSATABridge.identify_from_vid_pid(0xDEAD, 0xBEEF)
    assert info is None


def test_get_quirks_exact():
    quirks = USBToSATABridge.get_quirks(vid=0x152D, pid=0x0538)
    assert "no_48bit_lba" in quirks


def test_get_quirks_vendor_only():
    quirks = USBToSATABridge.get_quirks(vid=0x152D)
    assert isinstance(quirks, list)


def test_has_quirk_true():
    assert USBToSATABridge.has_quirk("no_48bit_lba", vid=0x152D, pid=0x0538)


def test_has_quirk_false():
    assert not USBToSATABridge.has_quirk("nvme_bridge", vid=0x152D, pid=0x0538)


def test_usb_bridge_list_not_empty():
    assert len(USBToSATABridge.BRIDGE_DB) > 20
