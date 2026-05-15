from hdd_firmware_toolkit.ata.commands import ATACmd, ATAError
from hdd_firmware_toolkit.ata.sat import SATCmd
from hdd_firmware_toolkit.ata.wd_vsc import WD_VSC
from hdd_firmware_toolkit.firmware.patcher import FirmwarePatch
from hdd_firmware_toolkit.firmware.samsung import SamsungSection
from hdd_firmware_toolkit.firmware.seagate import SeagateLODSection
from hdd_firmware_toolkit.firmware.toshiba import ToshibaFirmwareImage
from hdd_firmware_toolkit.firmware.wd import WDSection
from hdd_firmware_toolkit.hw.data_recovery import ReadRetryResult
from hdd_firmware_toolkit.hw.usb_bridge import USBBridgeInfo
from hdd_firmware_toolkit.nvme.admin import NVMeAdminCmd
from hdd_firmware_toolkit.samsung_mex.memory_map import SamsungFlashCmd


def test_wd_section_defaults():
    s = WDSection(0, 0x1000, 0, 1024, 2048, 0, False)
    assert s.index == 0
    assert s.base_addr == 0x1000


def test_samsung_section_defaults():
    s = SamsungSection(0, 0, 0, 1024)
    assert s.size == 1024


def test_seagate_lod_section():
    s = SeagateLODSection(0, 0, 512, 0x2000, 0, 0)
    assert s.load_addr == 0x2000
    assert s.id == 0


def test_toshiba_firmware_image_defaults():
    img = ToshibaFirmwareImage(0, 1024, 0x1000, 0, 0, b"")
    assert img.offset == 0
    assert img.size == 1024
    assert img.load_addr == 0x1000


def test_nvme_admin_cmd_defaults():
    cmd = NVMeAdminCmd(opcode=0x06, nsid=1)
    assert cmd.cdw10 == 0
    assert cmd.is_write is False


def test_read_retry_result():
    r = ReadRetryResult(0x100, True, b"data", 3, 1, "OK")
    assert r.lba == 0x100
    assert r.success is True


def test_usb_bridge_info():
    info = USBBridgeInfo(
        vendor_id=0x152D, product_id=0x0539,
        chip_name="JMS539", quirks=["no_48bit_lba"],
        sat_support=True,
    )
    assert info.vendor_id == 0x152D


def test_firmware_patch():
    p = FirmwarePatch(offset=0x100, original=b"\x00\x01",
                      replacement=b"\xFF\xFF", description="nop")
    assert p.offset == 0x100
    assert len(p.original) == 2


def test_ata_error():
    e = ATAError("test error")
    assert str(e) == "test error"


def test_atacmd_values():
    assert ATACmd.READ_DMA_EXT.value == 0x25
    assert ATACmd.WRITE_DMA_EXT.value == 0x35
    assert ATACmd.DOWNLOAD_MICRO.value == 0x92
    assert ATACmd.SMART.value == 0xB0


def test_samsung_flash_cmd_values():
    assert SamsungFlashCmd.ERASE.value == 0x05
    assert SamsungFlashCmd.WRITE_PAGE.value == 0x06
    assert SamsungFlashCmd.READ_PAGE.value == 0x07


def test_sat_cmd_values():
    assert SATCmd.ATA_PASS_THROUGH_16.value == 0x85
    assert SATCmd.ATA_PASS_THROUGH_12.value == 0xA1


def test_wd_vsc_values():
    assert WD_VSC.READ_RAM.value == 0x01
    assert WD_VSC.WRITE_RAM.value == 0x02
    assert WD_VSC.GET_VSC_LIST.value == 0xFF
