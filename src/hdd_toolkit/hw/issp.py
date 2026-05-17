from dataclasses import dataclass
from typing import ClassVar


@dataclass
class ISSPVector:
    """A single 22-bit ISSP vector as sent on the SDATA line."""

    bits: int
    length: int = 22

    def to_bytes(self) -> bytes:
        result = []
        remaining = self.bits
        bit_count = self.length
        while bit_count > 0:
            chunk = min(8, bit_count)
            shift = bit_count - chunk
            byte_val = (remaining >> shift) & ((1 << chunk) - 1)
            result.append(byte_val << (8 - chunk))
            remaining &= (1 << shift) - 1
            bit_count -= chunk
        return bytes(result)


class ISSPEngine:
    """
    Cypress In-System Serial Programming (ISSP) protocol engine.

    ISSP is the only interface that allows a host to interact with the
    CY8C21434 PSoC microcontroller used in the Aigo SK8671 self-encrypting
    drive to hold the user PIN.  OpenOCD JTAG (hw/jtag.py) cannot reach
    this device -- ISSP uses a completely different 3-wire protocol.

    Physical interface
    ------------------
    SCLK  -- clock output from host
    SDATA -- bidirectional data (open-drain; host drives for write, tristated for read)
    XRES  -- active-low reset, driven by host (GPIO output)

    ISSP entry sequence
    -------------------
    1. Assert XRES low for >= 10 us.
    2. Raise XRES while driving a 32-bit "magic" value on SDATA:
       0x01 CA 00 00  (0xCA = 0b11001010 == "magic key" high byte in Cypress docs)
    3. Send initialisation vectors (wrmem / wrreg commands that configure
       the supervisor ROM call interface in PSoC registers 0xF8-0xFA).
    4. Proceed with SROM syscall vectors.

    Vector encoding
    ---------------
    Each vector is 22 bits:  [2 stop bits][opcode 4b][addr 8b][data 8b]
    Opcode values:
      0x0  -- write memory (wrmem)
      0x2  -- read memory (rdmem) -- data bits become don't-care on output
      0x4  -- write register (wrreg)
      0x6  -- read register (rdreg)

    SROM syscall registers
    ----------------------
    0xF8  -- KEY1: first byte written before syscall opcode
    0xF9  -- KEY2: second key byte (Rigo: read as intermediate checksum temp)
    0xFA  -- SROM_PARAM: syscall opcode / parameter
    0xF1  -- temp register used by CHECKSUM-SETUP to accumulate partial sum

    Sources:
      - Rigo, "Hardcore Hacking a Self-Encrypting Hard Drive" (HackMag):
          ISSP entry sequence, vector encoding, SROM register map,
          cold-boot attack methodology
      - Cypress CY8C21434 datasheet / TRM:
          ISSP protocol, vector timing, SROM function table
      - Cypress AN2026A "ISSP Programming Specifications"
      - INVESTIGATION.md -- "Rigo -- Aigo SK8671 SED"
    """

    ISSP_MAGIC = 0x01CA0000
    ISSP_MAGIC_BITS = 32

    SROM_FN_READ_BLOCK = 0x00
    SROM_FN_WRITE_BLOCK = 0x01
    SROM_FN_ERASE_ALL = 0x05
    SROM_FN_CHECKSUM_SETUP = 0x07
    SROM_FN_VERIFY = 0x01

    PSOC_REG_KEY1 = 0xF8
    PSOC_REG_KEY2 = 0xF9
    PSOC_REG_SROM_PARAM = 0xFA
    PSOC_REG_TEMP = 0xF1

    OPCODE_WRMEM = 0x0
    OPCODE_RDMEM = 0x2
    OPCODE_WRREG = 0x4
    OPCODE_RDREG = 0x6

    INIT_VECTORS: ClassVar[list[int]] = [
        0x000000,
        0x000000,
        0x000000,
        0x000000,
        0x000000,
    ]

    def __init__(self):
        self._sram: dict[int, int] = {}

    @staticmethod
    def build_vector(opcode: int, address: int, data: int) -> ISSPVector:
        """
        Construct a 22-bit ISSP vector.

        Parameters
        ----------
        opcode  : 4-bit opcode (OPCODE_WRMEM / RDMEM / WRREG / RDREG)
        address : 8-bit register or memory address
        data    : 8-bit data value (ignored by read opcodes)
        """
        bits = ((opcode & 0xF) << 18) | ((address & 0xFF) << 10) | ((data & 0xFF) << 2)
        return ISSPVector(bits=bits, length=22)

    @staticmethod
    def entry_sequence() -> list[ISSPVector]:
        """
        Return the sequence of vectors that must be sent after XRES release
        to enter ISSP programming mode.

        The sequence ends with the init vectors that configure the SROM
        calling convention without overwriting KEY1/KEY2 in SRAM.
        """
        vectors = []
        for raw in ISSPEngine.INIT_VECTORS:
            vectors.append(ISSPVector(bits=raw))
        return vectors

    def write_reg(self, address: int, data: int) -> ISSPVector:
        """Build a write-register vector and apply it to the internal SRAM model."""
        self._sram[address] = data & 0xFF
        return self.build_vector(self.OPCODE_WRREG, address, data)

    def read_reg(self, address: int) -> ISSPVector:
        """Build a read-register vector."""
        return self.build_vector(self.OPCODE_RDREG, address, 0x00)

    def write_mem(self, address: int, data: int) -> ISSPVector:
        """Build a write-memory vector."""
        self._sram[address] = data & 0xFF
        return self.build_vector(self.OPCODE_WRMEM, address, data)

    def read_mem(self, address: int) -> ISSPVector:
        """Build a read-memory vector."""
        return self.build_vector(self.OPCODE_RDMEM, address, 0x00)

    def srom_call(self, fn: int) -> list[ISSPVector]:
        """
        Build the three-vector sequence that invokes an SROM syscall.

        SROM calling convention:
          1. wrreg KEY1 (0xF8) = 0x00
          2. wrreg KEY2 (0xF9) = 0x00
          3. wrreg SROM_PARAM (0xFA) = fn
        """
        return [
            self.write_reg(self.PSOC_REG_KEY1, 0x00),
            self.write_reg(self.PSOC_REG_KEY2, 0x00),
            self.write_reg(self.PSOC_REG_SROM_PARAM, fn),
        ]

    def checksum_setup_vectors(self) -> list[ISSPVector]:
        """
        Build vectors that invoke SROM function 0x07 (CHECKSUM-SETUP).

        CHECKSUM-SETUP starts a 16-bit additive checksum computation over
        all flash bytes.  The intermediate result accumulates in register
        0xF1 (temp) and registers KEY1/KEY2.  The cold-boot attack reads
        this intermediate state to extract one byte per timing step.
        """
        return self.srom_call(self.SROM_FN_CHECKSUM_SETUP)

    def read_security_data(self) -> list[ISSPVector]:
        """
        Build vectors to read the flash security byte table.

        Each flash block has a 2-bit security setting stored in a table
        readable after calling CHECKSUM-SETUP.  "Disable external read/write"
        (0b11) blocks all VERIFY and ROMX read attempts.
        """
        vectors = self.srom_call(self.SROM_FN_READ_BLOCK)
        for addr in range(0x00, 0x40):
            vectors.append(self.read_mem(addr))
        return vectors

    def get_sram_snapshot(self) -> dict[int, int]:
        """Return the current state of the internal SRAM model."""
        return dict(self._sram)

    def sync_sequence(self) -> list[ISSPVector]:
        """
        Produce the full ISSP synchronisation (entry) vector stream.

        This is the sequence sent once per power cycle before any SROM
        calls.  It does NOT include the init vectors that would overwrite
        KEY1/KEY2 -- those must be omitted for the cold-boot attack to work.
        """
        return self.entry_sequence()
