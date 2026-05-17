"""HDD Firmware Hacking Toolkit."""

from hdd_toolkit._version import __version__, __version_info__
from hdd_toolkit.ata.commands import (
    ATA_PASS_THROUGH_EX,
    SAMSUNG_840_EVO_FW_HISTORY,
    ATACmd,
    ATADevice,
    ATAError,
    ATASecurityCommands,
)
from hdd_toolkit.ata.sat import SATCmd, SATLayer
from hdd_toolkit.ata.seagate_vsc import SeagateF3SCTClient, SeagateSAModule
from hdd_toolkit.ata.wd_vsc import WD_SA_ROM_MAP, WD_VSC, WDVSCClient
from hdd_toolkit.cli.handlers import build_parser, main
from hdd_toolkit.core.utils import (
    _c,
    _hex_dump,
    diff_firmware,
    err,
    find_arm_function_tables,
    hdr,
    hexdump,
    info,
    ok,
    scan_strings,
    warn,
)
from hdd_toolkit.exploit.bridge_attack import ASM2362NVMeBridge
from hdd_toolkit.exploit.fw_update import FirmwareUpdateExploit
from hdd_toolkit.exploit.hotpatch import (
    HotPatchConfig,
    PatchTemplates,
    _bytes_to_asm,
    assemble_thumb,
    benchmark_reads,
    build_delay_hook,
    deploy_hot_patch,
)
from hdd_toolkit.exploit.psoc_coldboot import ColdBootResult, I2CDiff, PSoCColdBoot
from hdd_toolkit.exploit.service_area import ServiceArea, dump_all_overlays
from hdd_toolkit.exploit.spare_sector_forensics import SpareSectorForensics
from hdd_toolkit.firmware.detection import FirmwareDetection
from hdd_toolkit.firmware.patcher import FirmwarePatch, FirmwarePatcher
from hdd_toolkit.firmware.samsung import (
    SamsungFirmwareParser,
    SamsungSection,
    samsung_decode,
)
from hdd_toolkit.firmware.seagate import SeagateFWLoader, SeagateLODSection
from hdd_toolkit.firmware.toshiba import ToshibaFirmwareImage, ToshibaFirmwareParser
from hdd_toolkit.firmware.wd import LZHUFDecoder, WDFirmwareParser, WDSection
from hdd_toolkit.hw.data_recovery import ReadRetryResult, SATADataRecoveryOps
from hdd_toolkit.hw.hpa_dco import HPADCOAccess
from hdd_toolkit.hw.issp import ISSPEngine, ISSPVector
from hdd_toolkit.hw.jtag import OpenOCDBridge
from hdd_toolkit.hw.spi_flash import SPIFlashCapture, SPIFlashInfo, SPITransaction
from hdd_toolkit.hw.usb_bridge import USBBridgeInfo, USBToSATABridge
from hdd_toolkit.nvme.admin import (
    NVMeAdminCmd,
    NVMeAdminPassthrough,
    NVMeDevice,
    NvmePassthruCmd,
)
from hdd_toolkit.nvme.envme import eNVMeIntegration
from hdd_toolkit.nvme.ofabrics import NVMeOverFabrics
from hdd_toolkit.nvme.sandisk import SanDiskNVMeVSC
from hdd_toolkit.nvme.timing import NVMeTimingSideChannel
from hdd_toolkit.samsung_mex.aes import SamsungAESInfo
from hdd_toolkit.samsung_mex.dma import SamsungDMAHelper
from hdd_toolkit.samsung_mex.flash import SamsungFlashChannel
from hdd_toolkit.samsung_mex.gpio import SamsungGPIO
from hdd_toolkit.samsung_mex.memory_map import SamsungFlashCmd, SamsungMEXMap
from hdd_toolkit.samsung_mex.ncq import SamsungNCQParser
from hdd_toolkit.samsung_mex.safe_uart import SamsungSafeUARTClient

__all__ = [
    "ATA_PASS_THROUGH_EX",
    "SAMSUNG_840_EVO_FW_HISTORY",
    "WD_SA_ROM_MAP",
    "WD_VSC",
    "ASM2362NVMeBridge",
    "ATACmd",
    "ATADevice",
    "ATAError",
    "ATASecurityCommands",
    "ColdBootResult",
    "FirmwareDetection",
    "FirmwarePatch",
    "FirmwarePatcher",
    "FirmwareUpdateExploit",
    "HPADCOAccess",
    "HotPatchConfig",
    "I2CDiff",
    "ISSPEngine",
    "ISSPVector",
    "LZHUFDecoder",
    "NVMeAdminCmd",
    "NVMeAdminPassthrough",
    "NVMeDevice",
    "NVMeOverFabrics",
    "NVMeTimingSideChannel",
    "NvmePassthruCmd",
    "OpenOCDBridge",
    "PSoCColdBoot",
    "PatchTemplates",
    "ReadRetryResult",
    "SATADataRecoveryOps",
    "SATCmd",
    "SATLayer",
    "SPIFlashCapture",
    "SPIFlashInfo",
    "SPITransaction",
    "SamsungAESInfo",
    "SamsungDMAHelper",
    "SamsungFirmwareParser",
    "SamsungFlashChannel",
    "SamsungFlashCmd",
    "SamsungGPIO",
    "SamsungMEXMap",
    "SamsungNCQParser",
    "SamsungSafeUARTClient",
    "SamsungSection",
    "SanDiskNVMeVSC",
    "SeagateF3SCTClient",
    "SeagateFWLoader",
    "SeagateLODSection",
    "SeagateSAModule",
    "ServiceArea",
    "SpareSectorForensics",
    "ToshibaFirmwareImage",
    "ToshibaFirmwareParser",
    "USBBridgeInfo",
    "USBToSATABridge",
    "WDFirmwareParser",
    "WDSection",
    "WDVSCClient",
    "__version__",
    "__version_info__",
    "_bytes_to_asm",
    "_c",
    "_hex_dump",
    "assemble_thumb",
    "benchmark_reads",
    "build_delay_hook",
    "build_parser",
    "deploy_hot_patch",
    "diff_firmware",
    "dump_all_overlays",
    "eNVMeIntegration",
    "err",
    "find_arm_function_tables",
    "hdr",
    "hexdump",
    "info",
    "main",
    "ok",
    "samsung_decode",
    "scan_strings",
    "warn",
]
