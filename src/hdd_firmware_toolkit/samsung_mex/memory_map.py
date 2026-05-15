from enum import IntEnum
from typing import ClassVar


class SamsungMEXMap:
    """
    All known addresses and constants for the Samsung MEX controller
    (S4LN045X01-8030), three ARM Cortex-R4 cores at ~400 MHz.
    Derived from Philipp Maier's "The Missing Manual" (Samsung EVO 840 Repair Manual).

    Core naming used in the manual:
        mex1 = HCORE  - receives SATA commands, drives initial parsing
        mex2 = FCORE  - handles flash channels 0-3 (MEX2)
        mex3 = FCORE  - handles flash channels 4-7 (MEX3)
    In SAFE mode, only mex1 runs; mex2/mex3 are unpowered.
    """

    # == Tightly-Coupled Memory ===============================================
    ATCM_BASE = 0x00000000  # 96-128 KB per core (individual; mex1 sees
    #   SAFE-mode ROM here instead of ATCM)
    BTCM_BASE = 0x00800000  # 8 MB, shared by all three cores
    SPI_FLASH_BASE = 0x00000000  # 128 KB internal SPI flash (SAFE mode fw only)
    SPI_FLASH_SIZE = 0x00020000  #   normal fw lives in NAND SA, not here

    # == NCQ request buffers (BTCM) ===========================================
    # 33 slots = 16 bytes, base 0x00800C00 -- 0x00800E1F
    # NOTE: off-by-one vs ATA spec's 32 slots - may overflow into adjacent data
    NCQ_BASE = 0x00800C00
    NCQ_SLOT_SIZE = 0x10
    NCQ_SLOTS = 33  # BUG: ATA spec says 32; firmware compares <32
    #       then acts, writing a 33rd slot
    NCQ_CMD_OFFSET = 0x03  # byte offset of ATA command within slot
    NCQ_LBA_OFFSET = 0x04  # 6-byte LBA starts here (little-endian)
    NCQ_END = 0x00800E1F

    # == SATA PHY =============================================================
    SATA_STATUS_REG = 0x200000AC  # poll for COMINIT signal after power-on

    # == GPIO =================================================================
    GPIO_DIR_REG = 0x20501000  # bit=1 -- output, bit=0 -- input
    GPIO_VAL_REG = 0x20501004
    GPIO_MODE_REG = 0x20501008  # pinmux / drive-strength (write-only observed)
    # Bit assignments (from GPIO_VAL_REG / GPIO_DIR_REG):
    GPIO_UART_RX = 1 << 2
    GPIO_UART_TX = 1 << 3
    GPIO_I2C_SCL = 1 << 4
    GPIO_I2C_SDA = 1 << 5
    GPIO_SATA_COMINIT = 3 << 6  # bits 6+7
    GPIO_SATA_PIN11 = 1 << 9  # SATA power connector optional pin
    GPIO_SATA_IN_A = 1 << 10  # input from SATA core (unknown purpose)
    GPIO_SATA_IN_B = 1 << 11  # input from SATA core (unknown purpose)
    GPIO_FLASH_4CH = 1 << 16  # 0 = 2 flash channels/core, 1 = 4 channels/core
    GPIO_SAFE_MODE = 1 << 17  # sampled at boot; short to GND to enter SAFE mode
    GPIO_PAGES_CFG = 3 << 18  # NAND pages-per-block: value 2 -- 256 pages/block

    # == Flash power control ===================================================
    FLASH_PWR_REG = 0x20500004
    FLASH_PWR_ON = 0x0000070F  # written by firmware when flash needed
    FLASH_PWR_OFF = 0x00000300  # written when flash idle (power-saving)

    # == DMA controller (one per core; primary at 0x10010060) =================
    # Transfer granularity: always 8-byte blocks.
    # After firing, sleep 1 s instead of polling - avoids SATA timeout interference.
    DMA_BASE = 0x10010060
    DMA_STATUS = 0x10010060  # bit 4 = busy; write 0 to signal new/free
    DMA_SIZE = 0x10010064  # (byte_count // 8) - 1
    DMA_SRC = 0x10010068
    DMA_DST = 0x1001006C
    DMA_TRIGGER = 0x40004003  # OR into DMA_STATUS to fire
    # Copy target for SATA-exfiltration trick:
    #   DMA -- 0x85833000, then  dd if=/dev/sdX of=dump.bin bs=512 count=N
    DMA_SATA_WINDOW = 0x85833000
    DMA_SATA_WINDOW_SIZE = 0x19000000  # ~400 MB readable via SATA after DMA

    # == AES controller ========================================================
    # Only AES-XTS (mode 3) is actually used despite ECB/CBC support.
    # Keys are stored in NAND service area; MEX chip holds no persistent key state.
    # Tables in RAM are zeroed shortly after boot - dump immediately!
    AES_BASE = 0x20104000
    AES_CTRL = 0x20104000  # OR 0x10000 to start encrypt; poll bit 0x100000 to clear
    AES_KEY_SLOT = 0x20104050  # 64 bytes: key1[32] || key2[32]  (XTS needs 2 keys)
    AES_IV = 0x20104070  # 16-byte initialisation vector
    AES_PLAINTEXT = 0x20104090  # 16-byte input block
    AES_CIPHERTEXT = 0x20104100  # 16-byte output block
    AES_MODE_ECB = 1  # supported but unused
    AES_MODE_CBC = 2  # supported but unused
    AES_MODE_XTS = 3  # only mode used in practice

    # Encryption range/key tables (zeroed shortly after boot):
    ENC_RANGES_ADDR = 0x800200F4  # up to 20 range entries
    ENC_KEY_MAT_ADDR = 0x825E14  # 8 key slots = ~68 bytes (enabled + 2=32B keys)
    ENC_RANGE_ID_ARR = 0x800200E4  # 16-entry array mapping PHY slots to ranges
    KEY_SLOT_SYSTEM = 0xA  # key slot for the 289 MB shadow MBR / system area
    # Factory default layout (250 GB model):
    #   Range 0: KeySlot=0x0  LBA 0x1D24F970-0xFFFFFFFF  (large, likely unused tail)
    #   Range 1: KeySlot=0x0  LBA 0x00000000-0x1D1C5970  (250 GB user data)
    #   Range 2: KeySlot=0xA  LBA 0x1D1C5970-0x1D24F970  (289 MB shadow MBR)

    # == RNG ==================================================================
    RNG_BASE = 0x2050E000  # supplies up to 32 random bytes at a time

    # == UART (SAFE mode only) =================================================
    # 3.3 V logic, 115200 8N1.  Commands: rr (read32), rw (write32), ~ (fw update).
    # Designed for a proprietary Samsung tool, not human-readable terminal.
    UART_BASE = 0x20503000
    UART_TX = 0x20503014  # write =16 bits; only low 8 bits transmitted
    UART_RX = 0x20503018  # read received byte
    UART_BAUD = 115200
    UART_WAIT_CYCLES = 50  # firmware waits ~50 CPU cycles between r/w ops

    # == Flash channel base addresses =========================================
    # MEX2 controls channels 0-3, MEX3 controls channels 4-7.
    FLASH_CH_MEX2: ClassVar[list[int]] = [0x203C0000, 0x203D0000, 0x203E0000, 0x203F0000]
    FLASH_CH_MEX3: ClassVar[list[int]] = [0x204C0000, 0x204D0000, 0x204E0000, 0x204F0000]
    FLASH_CH_ALL = FLASH_CH_MEX2 + FLASH_CH_MEX3

    # Flash channel register offsets (add to channel base address):
    FCH_CMD = 0x3C00  # flash command byte
    FCH_PARAM1 = 0x3C04  # data/SA selector: 0x11=data r/w, 0x23=SA r/w, 0x01=r/w
    FCH_PARAM2 = 0x3C08  # 0x89+FTLbit=data, 0x10000007=write, 0x10000087=SA, 0x10A5=read
    FCH_PBPN = 0x3C54  # physical block+page number (low 8b = page, high = block)
    FCH_BITFIELD = 0x3C58  # 512-byte block selector: 0xFF=4KB, 0xFF00=4KB, 0xFFFF=8KB
    FCH_MEM_ADDR = 0x3C5C  # RAM address of 8 KB r/w buffer; 0x804E82xx=data, 0x84938xxx=SA
    # RUW (Read-Update-Write) extras for Service Area:
    FCH_RUW_PBPN = 0x3C9C  # PBPN + 0x100 (wear-levelling: read from N, write to N+0x100)
    FCH_RUW_BF = 0x3CA0  # bitfield for RUW (0xFFFF)
    FCH_RUW_MEM = 0x3CA4  # mem_addr + 0x4000

    # Flash dispatch / zone-select registers (shared across channels):
    FLASH_DISPATCH = 0x20380000  # destination selector: 0x3F | (channel<<10)
    FLASH_ZONE_SEL = 0x20380004  # zone + cmd: zone=0--chip1, zone=2--chip2; read=7, write=6
    FLASH_TRIGGER = 0x20380014  # write 1 to start transaction; auto-clears on completion
    FLASH_IRQ_ACK = 0x2038000C  # write back the value you read to acknowledge IRQ

    # Flash status register sentinel values:
    FLASH_STATUS_OK = 0xFFFF0000  # all good
    FLASH_STATUS_DONE = 0x7FFF8000  # read complete; ACK by writing same value back
    FLASH_STATUS_DEAD = 0x7FFF0000  # channel dead; no known recovery
    # Bits 0x700F0000 set -- hardware problem (seen on broken SSD)

    # Integrity check result register (per channel):
    FLASH_INTEGRITY_BASE = 0x20300050  # + channel index; 0xEC = OK, else bad
    FLASH_INTEGRITY_OK = 0xEC

    # == FTL demand-load parameters (250 GB model) ============================
    # FTL map is 466 MB (occupies most of the 512 MB LPDDR2).
    # Loaded into RAM on demand in chunks; one chunk = 3760 = 32 KB = 117.5 MB.
    # Must pre-load all chunks before a full RAM dump makes sense.
    FTL_CHUNK_SECTORS = 3760 * 64  # 117.5 MB expressed in 512-byte sectors
    FTL_CHUNKS_250GB = 2030  # chunks in a 250 GB model
    # FTL loaded-chunk bitarray locations in RAM:
    FTL_LOADED_MEX2 = 0x849E81A0
    FTL_LOADED_MEX3_A = 0x933E81A0
    FTL_LOADED_MEX3_B = 0x953741A0

    # == JTAG TAP instruction codes ============================================
    # Instructions 0-7 and 9, 12-13, 15: 1-bit (always 0), no boundary scan.
    JTAG_ABORT = 0x08  # JTAG_DP_ABORT - 32/37-bit register
    JTAG_DPACC = 0x0A  # JTAG_DP_DPACC - ARM debug port access
    JTAG_APACC = 0x0B  # JTAG_DP_APACC - returns 0x1843081A / 0x9A
    JTAG_IDCODE = 0x0E  # returns 0x4BA00477
    JTAG_BYPASS = 0x0F
    JTAG_KNOWN_IDCODE = 0x4BA00477
    # NOTE: no Boundary-Scan (EXTEST/SAMPLE) support - no BSDL file available.


# Samsung NAND flash command codes (sent to flash controller, not to NAND directly)
class SamsungFlashCmd(IntEnum):
    UNKNOWN_03 = 0x03  # unknown; sleep(600) or sleep(100) after; poll with STATUS
    ERASE = 0x05  # erase block; [+4]=0x03, [+8]=0xA4; used in fw-update path
    WRITE_PAGE = 0x06  # write 1-16 = 512B from RAM -- NAND (flash must be erased first)
    READ_PAGE = 0x07  # read 1-16 = 512B from NAND -- RAM
    INTEGRITY = 0x0A  # channel integrity check; [+8]=0x20; result at 0x20300050+ch
    STATUS = 0x0B  # poll completion of 0x03/0x10/0x11/0x17; bit 15 of [+0xC]
    PAGE_CMD_0E = 0x0E  # unknown page-oriented cmd; runs with timeout; checked every 500 cycles
    SET_INFO = 0x10  # write byte to ONFI info page; [+0x18]=1, [+0x1C]=addr, [+0x20]=val
    GET_INFO = 0x11  # read byte from ONFI info page; [+0x18]=1, [+0x1C]=addr; ret [+0x20]
    UNKNOWN_12 = 0x12  # seen addresses: 0x02, 0x30, 0x85, 0x8D, 0xA0, 0xA9
    UNKNOWN_14 = 0x14
    UNKNOWN_15 = 0x15
    UNKNOWN_17 = 0x17  # like 0x03; poll with STATUS
    UNKNOWN_18 = 0x18  # called before READ_PAGE; likely enables something
    UNKNOWN_19 = 0x19  # called after READ_PAGE; likely inverse of 0x18
    UNKNOWN_1C = 0x1C
    UNKNOWN_1D = 0x1D  # sends fixed values 0x30 or 0x66 as parameter
