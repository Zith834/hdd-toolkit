import struct
from typing import ClassVar

from hdd_toolkit.ata.sat import SATLayer


class HPADCOAccess:
    """
    ATA Host Protected Area (HPA) and Device Configuration Overlay (DCO)
    operations for covert storage, persistence, and forensic analysis.

    HPA: A hidden region at the end of the drive accessible via SET MAX
    ADDRESS. The OS never sees sectors beyond the HPA boundary. NSA's SWAP
    implant used HPA for OS-level persistence (ARKSTREAM/TWISTEDKILT modules).

    DCO: A vendor-configurable feature mask that hides capabilities from the
    OS. Malware can use DCO to disable security features or hide HPA support.

    Techniques implemented:
      - HPA detection: READ NATIVE MAX vs current max sector count
      - HPA creation: SET MAX ADDRESS (volatile or persistent)
      - DCO feature set enumeration via DEVICE CONFIGURATION IDENTIFY
      - DCO modification via DEVICE CONFIGURATION SET
      - Covert data storage in the HPA region

    Sources:
      - INVESTIGATION.md  -- "Schneier on Security -- NSA SWAP exploit":
          HPA used for OS-level persistence by Equation Group
      - INVESTIGATION.md  -- "2600 -- ATA Security Feature Set":
          ATA security commands reference including HPA interaction
      - INVESTIGATION.md  -- "CAPEC-402: Bypassing ATA Password Security":
          Factory mode access for HPA/DCO bypass
      - INVESTIGATION.md  -- "HDDSuperClone / HDDSuperTool":
          HPA read during cloning; skippable region for forensics
      - INVESTIGATION.md  -- "ACE Lab PC-3000":
          Professional HPA/DCO handling for data recovery
    """

    # ATA command opcodes for HPA
    READ_NATIVE_MAX_ADDR_EXT = 0x27
    READ_NATIVE_MAX_ADDR = 0xF8
    SET_MAX_ADDR_EXT = 0x37
    SET_MAX_ADDR = 0xF9
    # DCO command opcodes
    DEVICE_CONFIG_IDENTIFY = 0xB1
    DEVICE_CONFIG_SET = 0xB1
    DEVICE_CONFIG_RESTORE = 0xB1
    # DCO subcommands (feature register)
    DCO_IDENTIFY_SUBCMD = 0xC3
    DCO_SET_SUBCMD = 0xD1
    DCO_RESTORE_SUBCMD = 0xC0

    IDENTIFY_WORDS: ClassVar[dict[str, int]] = {
        "hpa_supported": 82,  # word 82, bit 10 = HPA supported
        "hpa_enabled": 83,  # word 83, bit 10 = HPA enabled
        "max_lba_28": 120,  # word 120-121: 28-bit max user LBA
        "native_max_28": 100,  # word 100-103: 28-bit native max
        "max_lba_48": 230,  # word 230-233: 48-bit max user LBA
        "native_max_48": 200,  # word 200-203: 48-bit native max
    }

    @staticmethod
    def detect_hpa_from_identify(identify_data: bytes) -> dict:
        """
        Parse IDENTIFY DEVICE data for HPA support flags and max addresses.
        NOTE: HPA activation can only be confirmed by comparing READ NATIVE
        MAX (a command) against words 60-61 / 100-103. This method reports
        the identify-data values and a best-effort HPA signal.

        ATA/ATAPI-8 word allocations:
          word  60-61:  28-bit total user LBA (current max in 28-bit mode)
          word  82:     bit 10 = HPA supported
          word  83:     bit 10 = HPA enabled
          word 100-103: 48-bit total user LBA (current max in 48-bit mode)
        """
        if len(identify_data) < 512:
            return {"hpa_active": False, "error": "identify data too short"}
        words = list(struct.unpack_from("<256H", identify_data, 0))
        hpa_supported = bool(words[82] & (1 << 10))
        hpa_enabled = bool(words[83] & (1 << 10))
        total_lba_28 = words[60] | (words[61] << 16)
        total_lba_48 = words[100] | (words[101] << 16) | (words[102] << 32) | (words[103] << 48)
        lba48 = bool(words[83] & (1 << 10))
        return {
            "hpa_active": None,  # requires READ NATIVE MAX command
            "hpa_supported": hpa_supported,
            "hpa_enabled": hpa_enabled,
            "total_lba_28": total_lba_28,
            "total_lba_48": total_lba_48 if lba48 else None,
            "lba48": lba48,
            "note": "HPA detection requires READ NATIVE MAX command; "
            "use hpa-build-cmd read-native then compare to total_lba_48",
        }

    @staticmethod
    def build_read_native_max_cmd(lba48: bool = True) -> bytes:
        """
        Build READ NATIVE MAX ADDRESS command CDB.
        Returns the true physical last LBA of the media.
        """
        return SATLayer.build_ata_pass_through_16(
            ata_cmd=HPADCOAccess.READ_NATIVE_MAX_ADDR_EXT
            if lba48
            else HPADCOAccess.READ_NATIVE_MAX_ADDR,
            lba=0,
            sector_count=1,
            protocol=4,
        )

    @staticmethod
    def build_set_max_cmd(lba: int, persistent: bool = True, lba48: bool = True) -> bytes:
        """
        Build SET MAX ADDRESS command CDB.
        Sets a new HPA boundary. If persistent=True, the change survives
        power cycle (SET MAX ADDRESS EXT with volatile=0).
        """
        if lba48:
            return SATLayer.build_ata_pass_through_16(
                ata_cmd=HPADCOAccess.SET_MAX_ADDR_EXT, lba=lba, sector_count=1, protocol=13
            )
        # 28-bit: SET MAX ADDRESS (0xF9) with feature reg
        return SATLayer.build_ata_pass_through_16(
            ata_cmd=HPADCOAccess.SET_MAX_ADDR, lba=lba, sector_count=1, protocol=13
        )

    @staticmethod
    def build_dco_identify_cmd() -> bytes:
        """
        Build DEVICE CONFIGURATION IDENTIFY command CDB.
        Passes subcommand 0xC3 via the features register.
        Reads the DCO feature set descriptor (512 bytes).
        """
        return SATLayer.build_ata_pass_through_16(
            ata_cmd=HPADCOAccess.DEVICE_CONFIG_IDENTIFY,
            features=HPADCOAccess.DCO_IDENTIFY_SUBCMD,
            sector_count=1,
            protocol=4,
        )

    @staticmethod
    def build_dco_set_cmd(dco_data: bytes) -> bytes:
        """
        Build DEVICE CONFIGURATION SET command CDB.
        Passes subcommand 0xD1 via the features register.
        """
        return SATLayer.build_ata_pass_through_16(
            ata_cmd=HPADCOAccess.DEVICE_CONFIG_SET,
            features=HPADCOAccess.DCO_SET_SUBCMD,
            sector_count=1,
            protocol=5,
        )

    @staticmethod
    def build_dco_restore_cmd() -> bytes:
        """Restore DCO to factory defaults (subcmd 0xC0)."""
        return SATLayer.build_ata_pass_through_16(
            ata_cmd=HPADCOAccess.DEVICE_CONFIG_RESTORE,
            features=HPADCOAccess.DCO_RESTORE_SUBCMD,
            sector_count=1,
            protocol=13,
        )

    @staticmethod
    def parse_dco_data(dco_data: bytes) -> dict:
        """
        Parse DCO feature set descriptor.
        Returns a dict of feature sets and whether they are enabled.
        """
        if len(dco_data) < 512:
            return {"error": "dco data too short"}
        words = list(struct.unpack_from("<256H", dco_data, 0))
        features = {}
        # Word 1: bits identify disabled feature sets
        feature_names = {
            0: "smart",
            1: "security",
            2: "removable_media",
            3: "power_management",
            4: "write_cache",
            5: "look_ahead",
            6: "hpa",
            7: "reliable_write",
            8: "tagged_command_queuing",
            10: "dma",
            11: "dco",
            12: "auto_standby",
        }
        disabled_mask = words[1]
        for bit, name in feature_names.items():
            features[name] = {
                "enabled": not bool(disabled_mask & (1 << bit)),
                "bit": bit,
            }
        return {
            "feature_count": bin(disabled_mask).count("1"),
            "features": features,
            "raw_words": words[:64],
        }


# =============================================================================
# NVMeTimingSideChannel -- NVMe timing covert channels
# =============================================================================
