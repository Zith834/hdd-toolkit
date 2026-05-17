import csv
import hashlib
import io
from dataclasses import dataclass, field
from typing import ClassVar


@dataclass
class SPITransaction:
    """A single decoded SPI transaction (one CS assertion)."""

    index: int
    mosi_bytes: bytes
    miso_bytes: bytes
    bit_count: int

    @property
    def opcode(self) -> int:
        return self.mosi_bytes[0] if self.mosi_bytes else 0

    @property
    def address(self) -> int:
        if len(self.mosi_bytes) >= 4:
            return int.from_bytes(self.mosi_bytes[1:4], "big")
        return 0


@dataclass
class SPIFlashInfo:
    """Decoded identity and firmware blob from a captured SPI session."""

    jedec_id: bytes = field(default_factory=bytes)
    manufacturer_id: int = 0
    device_id: int = 0
    capacity_bytes: int = 0
    firmware_blob: bytes = field(default_factory=bytes)
    sha1: str = ""
    transactions: list[SPITransaction] = field(default_factory=list)


class SPIFlashCapture:
    """
    Decoder for SPI flash captures made with a logic analyser (e.g. Saleae).

    The JMS539 USB-to-SATA bridge chip (used in the Aigo SK8671 SED)
    performs a bulk sequential read of its entire firmware from a
    Pm25LD010 SPI flash chip on every power-on.  Because the read is
    sequential and starts at address 0x000000, a single passive capture
    of one power cycle yields the full firmware image without any active
    interaction with the target.

    CSV format expected (Saleae Logic Analyser SPI analyser export):
      Packet ID, Time [s], Packet type, MOSI, MISO

    The MOSI / MISO cells contain either a decimal integer (for single-
    byte exports) or a hex string prefixed with "0x".

    Supported SPI flash opcodes (JEDEC standard):
      0x9F  -- READ JEDEC ID
      0x03  -- READ DATA (slow read, up to 25 MHz)
      0x0B  -- FAST READ (with 1 dummy byte after address)
      0xAB  -- RELEASE POWER-DOWN / READ DEVICE ID

    Sources:
      - Rigo, "Hardcore Hacking a Self-Encrypting Hard Drive" (HackMag)
      - Pm25LD010 datasheet (Chingis / ISSI):
          Power-on sequence, opcode table, 1 Mbit capacity
      - JMicron JMS539 application note:
          SPI flash boot sequence on power-on reset
      - INVESTIGATION.md -- "Rigo -- Aigo SK8671 SED"
    """

    SPI_OPCODE_READ_JEDEC_ID = 0x9F
    SPI_OPCODE_READ_DATA = 0x03
    SPI_OPCODE_FAST_READ = 0x0B
    SPI_OPCODE_READ_DEVICE_ID = 0xAB

    JEDEC_CAPACITY_MAP: ClassVar[dict[int, int]] = {
        0x10: 64 * 1024,
        0x11: 128 * 1024,
        0x12: 256 * 1024,
        0x13: 512 * 1024,
        0x14: 1 * 1024 * 1024,
        0x15: 2 * 1024 * 1024,
        0x16: 4 * 1024 * 1024,
        0x17: 8 * 1024 * 1024,
        0x18: 16 * 1024 * 1024,
    }

    @staticmethod
    def _parse_byte(cell: str) -> int:
        cell = cell.strip()
        if cell.startswith("0x") or cell.startswith("0X"):
            return int(cell, 16)
        if cell.isdigit():
            return int(cell)
        return 0

    @classmethod
    def decode_csv(cls, csv_text: str) -> SPIFlashInfo:
        """
        Parse a Saleae SPI analyser CSV export and reconstruct the firmware.

        Returns an SPIFlashInfo with the decoded JEDEC ID, capacity, firmware
        blob, SHA-1 hash, and list of individual transactions.
        """
        reader = csv.DictReader(io.StringIO(csv_text))
        transactions: list[SPITransaction] = []
        current_mosi: list[int] = []
        current_miso: list[int] = []
        current_index = 0

        for row in reader:
            ptype = (row.get("Packet type") or row.get("Type") or "").strip().lower()
            mosi_raw = row.get("MOSI") or row.get("mosi") or ""
            miso_raw = row.get("MISO") or row.get("miso") or ""

            if ptype in ("enable", "cs enable", "cs_enable", "start"):
                current_mosi = []
                current_miso = []
                current_index += 1
                continue

            if ptype in ("disable", "cs disable", "cs_disable", "end"):
                if current_mosi:
                    bit_count = len(current_mosi) * 8
                    tx = SPITransaction(
                        index=current_index,
                        mosi_bytes=bytes(current_mosi),
                        miso_bytes=bytes(current_miso),
                        bit_count=bit_count,
                    )
                    transactions.append(tx)
                current_mosi = []
                current_miso = []
                continue

            if ptype in ("data", "result", ""):
                if mosi_raw:
                    current_mosi.append(cls._parse_byte(mosi_raw))
                if miso_raw:
                    current_miso.append(cls._parse_byte(miso_raw))

        if current_mosi:
            transactions.append(
                SPITransaction(
                    index=current_index + 1,
                    mosi_bytes=bytes(current_mosi),
                    miso_bytes=bytes(current_miso),
                    bit_count=len(current_mosi) * 8,
                )
            )

        return cls._assemble_info(transactions)

    @classmethod
    def _assemble_info(cls, transactions: list[SPITransaction]) -> SPIFlashInfo:
        info = SPIFlashInfo(transactions=transactions)
        firmware_chunks: dict[int, bytes] = {}

        for tx in transactions:
            opcode = tx.opcode
            if opcode == cls.SPI_OPCODE_READ_JEDEC_ID and len(tx.miso_bytes) >= 4:
                info.jedec_id = tx.miso_bytes[1:4]
                info.manufacturer_id = tx.miso_bytes[1]
                info.device_id = (tx.miso_bytes[2] << 8) | tx.miso_bytes[3]
                capacity_code = tx.miso_bytes[3]
                info.capacity_bytes = cls.JEDEC_CAPACITY_MAP.get(capacity_code, 0)

            elif opcode == cls.SPI_OPCODE_READ_DATA and len(tx.mosi_bytes) >= 4:
                address = int.from_bytes(tx.mosi_bytes[1:4], "big")
                data = tx.miso_bytes[3:]
                if data:
                    firmware_chunks[address] = data

            elif opcode == cls.SPI_OPCODE_FAST_READ and len(tx.mosi_bytes) >= 5:
                address = int.from_bytes(tx.mosi_bytes[1:4], "big")
                data = tx.miso_bytes[5:]
                if data:
                    firmware_chunks[address] = data

        if firmware_chunks:
            max_addr = max(addr + len(data) for addr, data in firmware_chunks.items())
            blob = bytearray(max_addr)
            for addr, data in firmware_chunks.items():
                blob[addr : addr + len(data)] = data
            info.firmware_blob = bytes(blob)
            info.sha1 = hashlib.sha1(info.firmware_blob).hexdigest()

        return info

    @staticmethod
    def parse_jedec_id(jedec_id: bytes) -> dict:
        """
        Decode a 3-byte JEDEC manufacturer / device ID.

        Returns manufacturer name (if known), memory type, and density.
        """
        if len(jedec_id) < 3:
            return {"error": "jedec_id must be 3 bytes"}

        mfr_map: dict[int, str] = {
            0x9D: "ISSI / Chingis",
            0xEF: "Winbond",
            0xC8: "GigaDevice",
            0x20: "Micron / ST",
            0x01: "Spansion / Cypress",
            0x1F: "Atmel / Microchip",
            0xBF: "Microchip SST",
        }

        mem_type_map: dict[int, str] = {
            0x20: "SPI NOR Serial Flash",
            0x40: "SPI NOR Quad Flash",
            0x60: "SPI NOR Dual Flash",
        }

        mfr_id = jedec_id[0]
        mem_type = jedec_id[1]
        capacity_code = jedec_id[2]

        capacity = SPIFlashCapture.JEDEC_CAPACITY_MAP.get(capacity_code, 0)

        return {
            "manufacturer_id": mfr_id,
            "manufacturer": mfr_map.get(mfr_id, f"unknown (0x{mfr_id:02X})"),
            "memory_type": mem_type_map.get(mem_type & 0xE0, f"0x{mem_type:02X}"),
            "capacity_code": capacity_code,
            "capacity_bytes": capacity,
            "capacity_kb": capacity // 1024 if capacity else 0,
        }
