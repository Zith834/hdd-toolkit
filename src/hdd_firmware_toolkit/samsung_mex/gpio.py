from hdd_firmware_toolkit.core.utils import hdr
from hdd_firmware_toolkit.hw.jtag import OpenOCDBridge
from hdd_firmware_toolkit.samsung_mex.memory_map import SamsungMEXMap


class SamsungGPIO:
    """
    Read and write the Samsung MEX GPIO controller via JTAG/OpenOCD.

    Registers (SamsungMEXMap):
        GPIO_DIR_REG  0x20501000  - direction (1=output per bit)
        GPIO_VAL_REG  0x20501004  - value
        GPIO_MODE_REG 0x20501008  - pinmux / drive strength (observed write-only)

    Key bits:
        17  SAFE Mode pin - sampled once at boot; short to GND before power-on
        16  Flash channel config: 0=2ch/core, 1=4ch/core
        18-19 NAND pages-per-block (2 -- 256 pages/block observed)
        6-7 SATA COMINIT control
    """

    M = SamsungMEXMap

    def __init__(self, ocd: "OpenOCDBridge"):
        self.ocd = ocd

    def _rdw(self, addr: int) -> int:
        vals = self.ocd.read_memory(addr, 32, 1)
        return vals[0] if vals else 0

    def _mww(self, addr: int, val: int):
        self.ocd.cmd(f"mww 0x{addr:08X} 0x{val:08X}")

    def read_all(self) -> dict:
        direction = self._rdw(self.M.GPIO_DIR_REG)
        value = self._rdw(self.M.GPIO_VAL_REG)
        mode = self._rdw(self.M.GPIO_MODE_REG)
        return {
            "direction": direction,
            "value": value,
            "mode": mode,
            "safe_mode": bool(value & self.M.GPIO_SAFE_MODE),
            "uart_rx": bool(value & self.M.GPIO_UART_RX),
            "uart_tx": bool(value & self.M.GPIO_UART_TX),
            "i2c_scl": bool(value & self.M.GPIO_I2C_SCL),
            "i2c_sda": bool(value & self.M.GPIO_I2C_SDA),
            "flash_4ch": bool(value & self.M.GPIO_FLASH_4CH),
            "pages_cfg": (value & self.M.GPIO_PAGES_CFG) >> 18,
            "cominit": (value & self.M.GPIO_SATA_COMINIT) >> 6,
        }

    def set_output(self, bit_mask: int, high: bool = True):
        """Configure bit(s) as output and drive high or low."""
        direction = self._rdw(self.M.GPIO_DIR_REG)
        value = self._rdw(self.M.GPIO_VAL_REG)
        direction |= bit_mask
        if high:
            value |= bit_mask
        else:
            value &= ~bit_mask
        self._mww(self.M.GPIO_DIR_REG, direction)
        self._mww(self.M.GPIO_VAL_REG, value)

    def print_status(self):
        hdr("Samsung MEX GPIO Status")
        self.ocd.halt()
        self.read_all()
        self.ocd.resume()
