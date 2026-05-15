from hdd_firmware_toolkit.ata.commands import SAMSUNG_840_EVO_FW_HISTORY
from hdd_firmware_toolkit.samsung_mex.memory_map import SamsungMEXMap


def test_mex_map_constants():
    assert SamsungMEXMap.ATCM_BASE == 0x00000000
    assert SamsungMEXMap.BTCM_BASE == 0x00800000
    assert SamsungMEXMap.NCQ_BASE == 0x00800C00
    assert SamsungMEXMap.NCQ_SLOTS == 33
    assert SamsungMEXMap.GPIO_SAFE_MODE == (1 << 17)
    assert SamsungMEXMap.DMA_BASE == 0x10010060
    assert SamsungMEXMap.DMA_SATA_WINDOW == 0x85833000
    assert SamsungMEXMap.AES_BASE == 0x20104000
    assert SamsungMEXMap.UART_BAUD == 115200
    assert SamsungMEXMap.JTAG_KNOWN_IDCODE == 0x4BA00477


def test_mex_map_flash_channels():
    assert len(SamsungMEXMap.FLASH_CH_ALL) == 8
    assert SamsungMEXMap.FLASH_CH_ALL[4] == 0x204C0000


def test_samsung_fw_history():
    assert len(SAMSUNG_840_EVO_FW_HISTORY) >= 4
    versions = [entry[0] for entry in SAMSUNG_840_EVO_FW_HISTORY]
    assert "EXT0DB6Q" in versions
