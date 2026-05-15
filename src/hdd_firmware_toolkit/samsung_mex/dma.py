import time

from hdd_firmware_toolkit.core.utils import hdr, info, ok, warn
from hdd_firmware_toolkit.hw.jtag import OpenOCDBridge
from hdd_firmware_toolkit.samsung_mex.memory_map import SamsungMEXMap


class SamsungDMAHelper:
    """
    DMA-accelerated memory dump for Samsung MEX via JTAG (TheMissingManual, Layer 4).

    Workflow:
        1. Halt CPU via OpenOCD.
        2. Program DMA: source -- 0x85833000 (SATA window), size in 8-byte blocks.
        3. Write 0x40004003 to DMA_STATUS to fire.
        4. Resume CPU and sleep 1 s (do NOT poll - active waiting risks SATA timeout).
        5. Exfiltrate via block device:
               dd if=/dev/sdX of=dump.bin bs=512 count=<size//512>

    NOTE: BTCM starts at 0x00800000 (8 MB shared).  The FTL map in SDRAM is
    at higher addresses; pre-load it with FTL_CHUNK reads first if needed.
    """

    M = SamsungMEXMap

    def __init__(self, ocd: "OpenOCDBridge"):
        self.ocd = ocd

    def _mww(self, addr: int, val: int):
        self.ocd.cmd(f"mww 0x{addr:08X} 0x{val:08X}")

    def _mdw(self, addr: int) -> int:
        vals = self.ocd.read_memory(addr, 32, 1)
        return vals[0] if vals else 0

    def _wait_idle(self, timeout: float = 5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not (self._mdw(self.M.DMA_STATUS) & 0x10):
                return
            time.sleep(0.05)
        raise TimeoutError("DMA controller did not become idle in time")

    def copy_to_sata_window(self, src_addr: int, size: int, sleep_s: float = 1.0) -> int:
        """
        Copy `size` bytes from `src_addr` -- DMA_SATA_WINDOW (0x85833000).
        After sleeping `sleep_s` s, exfiltrate:
            dd if=<sata_dev> of=dump.bin bs=512 count=<size//512>
        Returns destination address (DMA_SATA_WINDOW).
        """
        if size <= 0 or size > 0x100000:
            raise ValueError(f"DMA size must be 1..1048576, got {size}")
        size_aligned = (size + 7) & ~7
        blocks_m1 = (size_aligned >> 3) - 1

        self.ocd.halt()
        self._wait_idle()
        self._mww(self.M.DMA_STATUS, 0)  # signal new transfer
        self._mww(self.M.DMA_SIZE, blocks_m1)
        self._mww(self.M.DMA_SRC, src_addr)
        self._mww(self.M.DMA_DST, self.M.DMA_SATA_WINDOW)
        self._mww(self.M.DMA_STATUS, self.M.DMA_TRIGGER)
        self.ocd.resume()

        info(
            f"DMA fired: 0x{src_addr:08X} -- "
            f"0x{self.M.DMA_SATA_WINDOW:08X}  ({size_aligned} bytes)"
        )
        info(f"Sleeping {sleep_s}s (do not poll - avoids SATA timeout)=")
        time.sleep(sleep_s)

        self.ocd.halt()
        self._mww(self.M.DMA_STATUS, 0)  # free controller
        self.ocd.resume()

        ok("DMA complete.  Exfiltrate with:")
        ok(f"  dd if=<sata_dev> of=dump.bin bs=512 count={size_aligned // 512}")
        return self.M.DMA_SATA_WINDOW

    def preload_ftl_map(self, sata_dev: str, size_gb: int = 250) -> None:
        """
        Pre-load the entire FTL map by reading one sector per 117.5 MB chunk.

        From TheMissingManual: the FTL map is demand-loaded from NAND into RAM
        on first access, in 117.5 MB chunks (3760 = 32 KB sectors).  A 250 GB
        SSD has 2030 such chunks.  This function reads one sector from each
        chunk, forcing all map entries into RAM so a full FTL dump is possible.
        """
        chunk_s = self.M.FTL_CHUNK_SECTORS
        total_s = (size_gb * 1024 * 1024 * 1024) // 512
        chunks = total_s // chunk_s

        hdr(f"FTL map pre-load: {chunks} = 117.5 MB chunks  ({sata_dev})")
        warn("This also triggers wear on the flash read-path.  Expected ~minutes.")

        import subprocess

        for i in range(chunks):
            lba = i * chunk_s
            subprocess.run(
                ["dd", f"if={sata_dev}", "of=/dev/null", "bs=512", "count=1", f"skip={lba}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if i % 200 == 0:
                info(f"  chunk {i:>4}/{chunks}  LBA 0x{lba:010X}")

        ok(
            f"FTL map fully pre-loaded: {chunks} chunks  "
            f"(bitarray at 0x{self.M.FTL_LOADED_MEX2:08X} should be all-ones)"
        )
