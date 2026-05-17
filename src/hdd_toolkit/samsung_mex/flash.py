import time

from hdd_toolkit.core.utils import hdr, info, ok, warn
from hdd_toolkit.hw.jtag import OpenOCDBridge
from hdd_toolkit.samsung_mex.memory_map import SamsungFlashCmd, SamsungMEXMap


class SamsungFlashChannel:
    """
    NAND flash channel read/write/erase/integrity operations for the Samsung
    MEX controller via JTAG/OpenOCD (TheMissingManual, "Flash" chapters).

    The MEX chip has 8 flash channels:
        MEX2 handles channels 0-3 (bases 0x203C0000-0x203F0000).
        MEX3 handles channels 4-7 (bases 0x204C0000-0x204F0000).

    Each channel has a block of registers at base + 0x3C00:
        FCH_CMD     (+0x00)  flash command byte (SamsungFlashCmd)
        FCH_PARAM1  (+0x04)  0x11=data r/w, 0x23=SA r/w
        FCH_PARAM2  (+0x08)  0x10A5=read, 0x10000007=data write, 0x10000087=SA write
        FCH_PBPN    (+0x54)  physical block+page: bits[15:8]=block, bits[7:0]=page
        FCH_BITFIELD(+0x58)  sector selector: 0xFF=4 KB, 0xFF00=4 KB, 0xFFFF=8 KB
        FCH_MEM_ADDR(+0x5C)  RAM address of 8 KB r/w buffer

    Global dispatch registers (shared):
        FLASH_DISPATCH (0x20380000)  destination: 0x3F | (channel << 10)
        FLASH_ZONE_SEL (0x20380004)  (zone << 4) | op: zone 0=chip1 zone 2=chip2;
                                     op 7=read, 6=write
        FLASH_TRIGGER  (0x20380014)  write 1 to start; auto-clears on completion
        FLASH_IRQ_ACK  (0x2038000C)  write back the value read to acknowledge IRQ

    Service-Area RUW (Read-Update-Write) registers (for SA modification):
        FCH_RUW_PBPN (+0x9C)  PBPN + 0x100 (read from block N, write to N+0x100)
        FCH_RUW_BF   (+0xA0)  bitfield for RUW (0xFFFF)
        FCH_RUW_MEM  (+0xA4)  mem_addr + 0x4000

    Sources: Philipp Maier, "The Missing Manual" (Samsung EVO 840 Repair Manual)
    """

    DATA_PARAM1 = 0x11
    SA_PARAM1 = 0x23
    PARAM2_READ = 0x10A5
    PARAM2_DATA_WRITE = 0x10000007
    PARAM2_SA_WRITE = 0x10000087
    BITFIELD_8KB = 0xFFFF
    BITFIELD_4KB_LO = 0x00FF
    BITFIELD_4KB_HI = 0xFF00
    OP_READ = 7
    OP_WRITE = 6
    ZONE_CHIP1 = 0
    ZONE_CHIP2 = 2

    M = SamsungMEXMap

    def __init__(self, ocd: "OpenOCDBridge", channel: int):
        if not (0 <= channel <= 7):
            raise ValueError(f"Channel must be 0-7, got {channel}")
        self.ocd = ocd
        self.channel = channel
        self._ch_base = self.M.FLASH_CH_ALL[channel]

    def _mww(self, addr: int, val: int) -> None:
        self.ocd.cmd(f"mww 0x{addr:08X} 0x{val:08X}")

    def _mdw(self, addr: int) -> int:
        vals = self.ocd.read_memory(addr, 32, 1)
        return vals[0] if vals else 0

    def _fch(self, offset: int) -> int:
        return self._ch_base + offset

    def _set_dispatch(self, zone: int, op: int) -> None:
        dispatch = 0x3F | (self.channel << 10)
        self._mww(self.M.FLASH_DISPATCH, dispatch)
        zone_sel = (zone << 4) | (op & 0xF)
        self._mww(self.M.FLASH_ZONE_SEL, zone_sel)

    def _trigger_and_wait(self, timeout: float = 5.0) -> None:
        self._mww(self.M.FLASH_TRIGGER, 1)
        deadline = time.time() + timeout
        while time.time() < deadline:
            status = self._mdw(self.M.FLASH_TRIGGER)
            if status == 0:
                return
            time.sleep(0.01)
        irq_val = self._mdw(self.M.FLASH_IRQ_ACK)
        if irq_val:
            self._mww(self.M.FLASH_IRQ_ACK, irq_val)
        raise TimeoutError(f"Flash trigger did not clear in {timeout}s on channel {self.channel}")

    def _check_status(self) -> bool:
        status = self._mdw(self.M.FLASH_DISPATCH)
        if status == self.M.FLASH_STATUS_DEAD:
            warn(f"Channel {self.channel}: FLASH_STATUS_DEAD (0x{status:08X}) - no recovery")
            return False
        if status == self.M.FLASH_STATUS_DONE:
            irq_val = self._mdw(self.M.FLASH_IRQ_ACK)
            if irq_val:
                self._mww(self.M.FLASH_IRQ_ACK, irq_val)
        return True

    def check_integrity(self) -> bool:
        """
        Run a flash channel integrity check (SamsungFlashCmd.INTEGRITY = 0x0A).
        Result at FLASH_INTEGRITY_BASE + channel: 0xEC = OK, else bad.
        Returns True if the channel reports healthy.
        """
        self.ocd.halt()
        self._mww(self._fch(self.M.FCH_CMD), SamsungFlashCmd.INTEGRITY)
        self._mww(self._fch(self.M.FCH_PARAM2), 0x20)
        self._set_dispatch(self.ZONE_CHIP1, self.OP_READ)
        self._trigger_and_wait()
        result = self._mdw(self.M.FLASH_INTEGRITY_BASE + self.channel)
        self.ocd.resume()
        ok_flag = result == self.M.FLASH_INTEGRITY_OK
        if ok_flag:
            ok(f"Channel {self.channel}: integrity OK (0x{result:02X})")
        else:
            warn(f"Channel {self.channel}: integrity FAIL (0x{result:02X}, expected 0x{self.M.FLASH_INTEGRITY_OK:02X})")
        return ok_flag

    def read_page(
        self,
        block: int,
        page: int,
        mem_addr: int = SamsungMEXMap.DMA_SATA_WINDOW,
        bitfield: int = BITFIELD_8KB,
        zone: int = ZONE_CHIP1,
    ) -> bool:
        """
        Read one NAND page into RAM.

        block     Physical block number.
        page      Page within that block (0-255).
        mem_addr  Destination RAM address.  Use DMA_SATA_WINDOW (0x85833000)
                  to exfiltrate via SATA dd after the operation.
        bitfield  Sector selector: 0xFFFF = 8 KB (full page), 0x00FF / 0xFF00 = 4 KB half.
        zone      0 = chip1, 2 = chip2.

        Returns True on success (status not DEAD).
        """
        pbpn = ((block & 0xFFFFFF) << 8) | (page & 0xFF)
        self.ocd.halt()
        self._mww(self._fch(self.M.FCH_PBPN), pbpn)
        self._mww(self._fch(self.M.FCH_BITFIELD), bitfield)
        self._mww(self._fch(self.M.FCH_MEM_ADDR), mem_addr)
        self._mww(self._fch(self.M.FCH_PARAM1), self.DATA_PARAM1)
        self._mww(self._fch(self.M.FCH_PARAM2), self.PARAM2_READ)
        self._mww(self._fch(self.M.FCH_CMD), SamsungFlashCmd.READ_PAGE)
        self._set_dispatch(zone, self.OP_READ)
        self._trigger_and_wait()
        ok_flag = self._check_status()
        self.ocd.resume()
        if ok_flag:
            info(
                f"Flash read: ch{self.channel} block=0x{block:X} page=0x{page:X} "
                f"-> RAM 0x{mem_addr:08X}"
            )
        return ok_flag

    def write_page(
        self,
        block: int,
        page: int,
        mem_addr: int,
        bitfield: int = BITFIELD_8KB,
        zone: int = ZONE_CHIP1,
    ) -> bool:
        """
        Write one NAND page from RAM.  The target block must be erased first.

        block     Physical block number.
        page      Page within that block (0-255).
        mem_addr  Source RAM address of the 8 KB data buffer.
        bitfield  Sector selector (default 0xFFFF = full 8 KB page).
        zone      0 = chip1, 2 = chip2.
        """
        pbpn = ((block & 0xFFFFFF) << 8) | (page & 0xFF)
        self.ocd.halt()
        self._mww(self._fch(self.M.FCH_PBPN), pbpn)
        self._mww(self._fch(self.M.FCH_BITFIELD), bitfield)
        self._mww(self._fch(self.M.FCH_MEM_ADDR), mem_addr)
        self._mww(self._fch(self.M.FCH_PARAM1), self.DATA_PARAM1)
        self._mww(self._fch(self.M.FCH_PARAM2), self.PARAM2_DATA_WRITE)
        self._mww(self._fch(self.M.FCH_CMD), SamsungFlashCmd.WRITE_PAGE)
        self._set_dispatch(zone, self.OP_WRITE)
        self._trigger_and_wait()
        ok_flag = self._check_status()
        self.ocd.resume()
        if ok_flag:
            info(
                f"Flash write: ch{self.channel} block=0x{block:X} page=0x{page:X} "
                f"from RAM 0x{mem_addr:08X}"
            )
        return ok_flag

    def erase_block(self, block: int, zone: int = ZONE_CHIP1) -> bool:
        """
        Erase a NAND block.

        block  Physical block number to erase.
        zone   0 = chip1, 2 = chip2.

        NOTE: After erasing, set FCH_PARAM1=0x03 and FCH_PARAM2=0xA4 for the
        status poll (SamsungFlashCmd.STATUS = 0x0B).
        """
        pbpn = (block & 0xFFFFFF) << 8
        self.ocd.halt()
        self._mww(self._fch(self.M.FCH_PBPN), pbpn)
        self._mww(self._fch(self.M.FCH_PARAM1), 0x03)
        self._mww(self._fch(self.M.FCH_PARAM2), 0xA4)
        self._mww(self._fch(self.M.FCH_CMD), SamsungFlashCmd.ERASE)
        self._set_dispatch(zone, self.OP_WRITE)
        self._trigger_and_wait()
        ok_flag = self._check_status()
        self.ocd.resume()
        if ok_flag:
            info(f"Flash erase: ch{self.channel} block=0x{block:X}")
        return ok_flag

    def read_sa_page(
        self,
        block: int,
        page: int,
        mem_addr: int,
        zone: int = ZONE_CHIP1,
    ) -> bool:
        """
        Read a Service Area page.

        Uses SA parameters (PARAM1=0x23, PARAM2=0x10A5).
        Standard SA buffer RAM addresses: 0x84938000-0x84938xxx.
        """
        pbpn = ((block & 0xFFFFFF) << 8) | (page & 0xFF)
        self.ocd.halt()
        self._mww(self._fch(self.M.FCH_PBPN), pbpn)
        self._mww(self._fch(self.M.FCH_BITFIELD), self.BITFIELD_8KB)
        self._mww(self._fch(self.M.FCH_MEM_ADDR), mem_addr)
        self._mww(self._fch(self.M.FCH_PARAM1), self.SA_PARAM1)
        self._mww(self._fch(self.M.FCH_PARAM2), self.PARAM2_READ)
        self._mww(self._fch(self.M.FCH_CMD), SamsungFlashCmd.READ_PAGE)
        self._set_dispatch(zone, self.OP_READ)
        self._trigger_and_wait()
        ok_flag = self._check_status()
        self.ocd.resume()
        if ok_flag:
            info(
                f"SA read: ch{self.channel} block=0x{block:X} page=0x{page:X} "
                f"-> RAM 0x{mem_addr:08X}"
            )
        return ok_flag

    def write_sa_ruw(
        self,
        block: int,
        page: int,
        mem_addr: int,
        zone: int = ZONE_CHIP1,
    ) -> bool:
        """
        Read-Update-Write for Service Area modification.

        Reads from block N, writes updated contents to block N+0x100
        (wear-levelling scheme used by MEX firmware for SA updates).

        FCH_RUW_PBPN = PBPN + 0x100  (destination block offset)
        FCH_RUW_BF   = 0xFFFF
        FCH_RUW_MEM  = mem_addr + 0x4000

        Sources: TheMissingManual flash channel RUW register table.
        """
        pbpn = ((block & 0xFFFFFF) << 8) | (page & 0xFF)
        ruw_pbpn = pbpn + 0x100
        self.ocd.halt()
        self._mww(self._fch(self.M.FCH_PBPN), pbpn)
        self._mww(self._fch(self.M.FCH_BITFIELD), self.BITFIELD_8KB)
        self._mww(self._fch(self.M.FCH_MEM_ADDR), mem_addr)
        self._mww(self._fch(self.M.FCH_PARAM1), self.SA_PARAM1)
        self._mww(self._fch(self.M.FCH_PARAM2), self.PARAM2_SA_WRITE)
        self._mww(self._fch(self.M.FCH_RUW_PBPN), ruw_pbpn)
        self._mww(self._fch(self.M.FCH_RUW_BF), self.BITFIELD_8KB)
        self._mww(self._fch(self.M.FCH_RUW_MEM), mem_addr + 0x4000)
        self._mww(self._fch(self.M.FCH_CMD), SamsungFlashCmd.WRITE_PAGE)
        self._set_dispatch(zone, self.OP_WRITE)
        self._trigger_and_wait()
        ok_flag = self._check_status()
        self.ocd.resume()
        if ok_flag:
            info(
                f"SA RUW: ch{self.channel} block=0x{block:X}->0x{block + 0x100:X} "
                f"page=0x{page:X} mem=0x{mem_addr:08X}"
            )
        return ok_flag

    def print_status(self) -> None:
        hdr(f"Samsung Flash Channel {self.channel} Status")
        info(f"  Base address : 0x{self._ch_base:08X}")
        info(f"  FCH_CMD      : 0x{self._fch(self.M.FCH_CMD):08X}")
        info(f"  FCH_PBPN     : 0x{self._fch(self.M.FCH_PBPN):08X}")
        info(f"  FCH_MEM_ADDR : 0x{self._fch(self.M.FCH_MEM_ADDR):08X}")
        info(f"  FLASH_DISPATCH: 0x{self.M.FLASH_DISPATCH:08X}")
        info(f"  FLASH_TRIGGER : 0x{self.M.FLASH_TRIGGER:08X}")
        info(f"  Integrity reg : 0x{self.M.FLASH_INTEGRITY_BASE + self.channel:08X}")
