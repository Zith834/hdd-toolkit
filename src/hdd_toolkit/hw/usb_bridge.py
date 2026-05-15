from dataclasses import dataclass
from typing import ClassVar


@dataclass
class USBBridgeInfo:
    """USB bridge chip identification and quirk data."""

    vendor_id: int
    product_id: int
    chip_name: str
    quirks: list
    sat_support: bool
    vsc_protocol: str = ""
    max_speed: str = ""
    notes: str = ""


class USBToSATABridge:
    """
    Detect and characterize USB-to-SATA/NVMe bridge chips.
    Many common USB-SATA enclosures expose drives via SCSI-ATA Translation
    (SAT) or vendor-specific SCSI commands.  Knowing the bridge chip is
    essential for issuing vendor-specific ATA commands (VSCs), firmware
    updates, and working around quirks.

    Detection is done via SCSI INQUIRY string parsing. The INQUIRY
    vendor+product fields often leak the bridge chip identity:
      "JMicron   Generic"        -- JMicron JMS539/JMS561
      "ASMT      ASM105x"        -- ASMedia 105x/115x/135x/235x
      "Initio    IS621"          -- Initio INIC-160X/360X
      "Cypress   USB2.0-SATA"    -- Cypress EZ-USB FX2 (CY7C68013)
      "SYSTEM    BRIDGE"         -- Sunplus SPIF215
      "LG        HL-DT-ST"       -- LG optical drives (MTK / Renesas)
      "USB3.0    SATA"           -- Generic VL716 / ASM135x
      "Macintosh  HD"            -- Apple USB-C (T2/ACL bridge)

    Usage:
        inq = USBToSATABridge.identify_from_inquiry("JMicron   Generic")
        # inq.chip_name -- "JMS539"
        quirks = USBToSATABridge.get_quirks(vid=0x152D, pid=0x0539)

    Sources:
      - INVESTIGATION.md  -- "asm2362-tool / NVMe recovery (Jess Sullivan)":
          ASM2362 XRAM debug -- primary reference for NVMe bridge injection
      - INVESTIGATION.md  -- "JMicron JMS583 USB NVMe bridge":
          Open-source JMS583 interface with VSC passthrough
      - INVESTIGATION.md  -- "Linux USB storage quirks driver":
          Kernel quirks affecting SATA bridge behavior
      - INVESTIGATION.md  -- "SAT-4 Standard (T10/2088-D, r06)":
          SAT protocol used by most modern USB-to-SATA bridges
    """

    # Known USB bridge VID/PID pairs
    BRIDGE_DB: ClassVar[list[USBBridgeInfo]] = [
        # JMicron
        USBBridgeInfo(
            0x152D,
            0x0538,
            "JMS538",
            ["no_48bit_lba", "needs_ufi"],
            True,
            "SAT",
            "USB 3.0",
            "Older JMicron bridge",
        ),
        USBBridgeInfo(
            0x152D,
            0x0539,
            "JMS539",
            ["no_48bit_lba", "needs_ufi"],
            True,
            "SAT",
            "USB 3.0",
            "Common in WD Elements enclosures",
        ),
        USBBridgeInfo(
            0x152D, 0x0561, "JMS561", [], True, "SAT", "USB 3.0", "Two-port JMicron bridge"
        ),
        USBBridgeInfo(
            0x152D,
            0x0578,
            "JMS578",
            ["vsc_passphrase"],
            True,
            "SAT",
            "USB 3.0",
            "Needs passphrase for VSC access",
        ),
        USBBridgeInfo(
            0x152D,
            0x0580,
            "JMS580",
            ["vsc_passphrase", "ufi_only"],
            True,
            "SAT",
            "USB 3.1",
            "USB-C bridge",
        ),
        USBBridgeInfo(
            0x152D,
            0x0583,
            "JMS583",
            ["nvme_bridge"],
            True,
            "SAT",
            "USB 3.1",
            "USB-C NVMe bridge (ASM2362 competitor)",
        ),
        # ASMedia
        USBBridgeInfo(
            0x174C, 0x1153, "ASM1153", [], True, "SAT", "USB 3.0", "Widely used in DIY enclosures"
        ),
        USBBridgeInfo(0x174C, 0x1351, "ASM1351", [], True, "SAT", "USB 3.1", "SATA III bridge"),
        USBBridgeInfo(0x174C, 0x235C, "ASM235CM", [], True, "SAT", "USB 3.2", "SATA III bridge"),
        USBBridgeInfo(
            0x174C,
            0x2362,
            "ASM2362",
            ["nvme_bridge", "xram_inject"],
            True,
            "SAT",
            "USB 3.1",
            "NVMe bridge with XRAM debug",
        ),
        USBBridgeInfo(
            0x174C,
            0x2364,
            "ASM2364",
            ["nvme_bridge"],
            True,
            "SAT",
            "USB 3.1",
            "NVMe bridge, 4-lane PCIe",
        ),
        # Initio
        USBBridgeInfo(
            0x13FD,
            0x1609,
            "INIC-1609",
            ["no_sat"],
            True,
            "VSC",
            "USB 2.0",
            "Older Initio (VSC-based, not SAT)",
        ),
        USBBridgeInfo(
            0x13FD,
            0x1650,
            "INIC-1650",
            ["no_sat"],
            True,
            "VSC",
            "USB 2.0",
            "Used in some Seagate enclosures",
        ),
        USBBridgeInfo(
            0x13FD, 0x3609, "INIC-3609", [], True, "SAT", "USB 3.0", "Newer Initio with SAT"
        ),
        # Cypress
        USBBridgeInfo(
            0x04B4,
            0x6830,
            "CY7C68013",
            ["fx2_fw_load"],
            False,
            "custom",
            "USB 2.0",
            "EZ-USB FX2: firmware-loadable, used in research",
        ),
        USBBridgeInfo(
            0x04B4, 0x8613, "CY7C65642", [], False, "none", "USB 2.0", "HUB + SATA bridge combo"
        ),
        # Sunplus
        USBBridgeInfo(
            0x1B6F, 0x0215, "SPIF215", [], True, "SAT", "USB 3.0", "Common in cheap enclosures"
        ),
        USBBridgeInfo(
            0x1B6F, 0x0220, "SPIF225", [], True, "SAT", "USB 3.0", "Newer Sunplus bridge"
        ),
        # VIA / VL
        USBBridgeInfo(0x2109, 0x0711, "VL711", [], True, "SAT", "USB 3.0", "VIA Labs SATA bridge"),
        USBBridgeInfo(0x2109, 0x0715, "VL715", [], True, "SAT", "USB 3.1", "VIA Labs NVMe bridge"),
        USBBridgeInfo(
            0x2109, 0x0716, "VL716", [], True, "SAT", "USB 3.1", "VIA Labs SATA bridge (USB-C)"
        ),
        # Realtek
        USBBridgeInfo(
            0x0BDA,
            0x0480,
            "RTL9210",
            ["nvme_bridge", "ufi_needed"],
            True,
            "SAT",
            "USB 3.1",
            "Realtek NVMe/SATA dual protocol",
        ),
        USBBridgeInfo(
            0x0BDA, 0x0482, "RTL9210B", ["nvme_bridge"], True, "SAT", "USB 3.1", "RTL9210 rev B"
        ),
        USBBridgeInfo(
            0x0BDA,
            0x0485,
            "RTL9220DP",
            ["nvme_bridge"],
            True,
            "SAT",
            "USB 3.2",
            "Realtek DP-alt NVMe",
        ),
    ]

    # INQUIRY string -- chip family mapping
    INQUIRY_MAP: ClassVar[list[tuple[str, str]]] = [
        ("JMicron", "jmicron"),
        ("ASMT", "asmedia"),
        ("ASM", "asmedia"),
        ("Initio", "initio"),
        ("Cypress", "cypress"),
        ("Sunplus", "sunplus"),
        ("SYSTEM", "sunplus"),
        ("VL", "via"),
        ("VIA", "via"),
        ("Realtek", "realtek"),
        ("RTL", "realtek"),
        ("LG", "lg_optical"),
        ("HL-DT", "lg_optical"),
        ("Apple", "apple_t2"),
        ("Macintosh", "apple_t2"),
        ("Samsung", "samsung_t5"),  # Samsung T5 SSD (ASM1153E inside)
    ]

    # Known INQUIRY vendor strings for direct lookup
    KNOWN_VENDOR_STRINGS: ClassVar[dict[str, tuple[str, str]]] = {
        "JMicron  Generic": ("JMicron", "JMS539"),
        "JMicron             ": ("JMicron", "JMS578"),
        "ASMT     ASM1153": ("ASMedia", "ASM1153"),
        "ASMT     2105": ("ASMedia", "ASM1153E"),
        "ASMT     2115": ("ASMedia", "ASM1153"),
        "ASMT     1351": ("ASMedia", "ASM1351"),
        "ASMT     2362": ("ASMedia", "ASM2362"),
        "Initio   IS621": ("Initio", "INIC-1609"),
        "Cypress  USB2.0": ("Cypress", "CY7C68013"),
        "SYSTEM   BRIDGE": ("Sunplus", "SPIF215"),
        "VL716             ": ("VIA", "VL716"),
        "RTL9210            ": ("Realtek", "RTL9210"),
        "Samsung T5         ": ("Samsung", "ASM1153E"),
        "Samsung Portable": ("Samsung", "ASM2362"),
    }

    @classmethod
    def identify_from_inquiry(
        cls, inquiry_vendor: str, inquiry_product: str = ""
    ) -> USBBridgeInfo:
        """
        Identify bridge chip from SCSI INQUIRY vendor/product strings.
        Returns a USBBridgeInfo with the closest match, or a generic placeholder.
        """
        combined = f"{inquiry_vendor} {inquiry_product}".strip()

        for known, (chip_vendor, chip) in cls.KNOWN_VENDOR_STRINGS.items():
            if combined.startswith(known[:8]):
                for bi in cls.BRIDGE_DB:
                    if chip.lower() in bi.chip_name.lower():
                        return bi

        # Fallback: search known DB by matching VID if we have it
        return USBBridgeInfo(
            vendor_id=0,
            product_id=0,
            chip_name=inquiry_vendor.strip() or "generic",
            quirks=["unknown"],
            sat_support=True,
            vsc_protocol="SAT",
            notes=f"Uncertain: INQ vendor={inquiry_vendor!r} product={inquiry_product!r}",
        )

    @classmethod
    def identify_from_vid_pid(cls, vid: int, pid: int) -> USBBridgeInfo | None:
        """Look up bridge chip by USB vendor ID / product ID."""
        for bi in cls.BRIDGE_DB:
            if bi.vendor_id == vid and bi.product_id == pid:
                return bi
        return None

    @classmethod
    def get_quirks(cls, vid: int = 0, pid: int = 0, chip_name: str = "") -> list[str]:
        """Get list of known quirks for a bridge chip."""
        if vid or pid:
            bi = cls.identify_from_vid_pid(vid, pid)
            if bi:
                return bi.quirks
        for bi in cls.BRIDGE_DB:
            if chip_name.lower() in bi.chip_name.lower():
                return bi.quirks
        return []

    @classmethod
    def has_quirk(cls, quirk: str, vid: int = 0, pid: int = 0, chip_name: str = "") -> bool:
        """Check if a bridge chip has a specific quirk."""
        return quirk in cls.get_quirks(vid=vid, pid=pid, chip_name=chip_name)


# =============================================================================
# SATA Data Recovery Operations
# =============================================================================
