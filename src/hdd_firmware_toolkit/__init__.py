"""HDD Firmware Hacking Toolkit."""

from hdd_firmware_toolkit._version import __version__, __version_info__
from hdd_firmware_toolkit.ata.commands import (
    ATA_PASS_THROUGH_EX,
    SAMSUNG_840_EVO_FW_HISTORY,
    ATACmd,
    ATADevice,
    ATAError,
    ATASecurityCommands,
)
from hdd_firmware_toolkit.ata.sat import SATCmd, SATLayer
from hdd_firmware_toolkit.ata.wd_vsc import WD_VSC, WDVSCClient
from hdd_firmware_toolkit.cli.handlers import build_parser, main
from hdd_firmware_toolkit.core.utils import (
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
from hdd_firmware_toolkit.exploit.bridge_attack import ASM2362NVMeBridge
from hdd_firmware_toolkit.exploit.fw_update import FirmwareUpdateExploit
from hdd_firmware_toolkit.exploit.hotpatch import (
    HotPatchConfig,
    PatchTemplates,
    _bytes_to_asm,
    assemble_thumb,
    benchmark_reads,
    build_delay_hook,
    deploy_hot_patch,
)
from hdd_firmware_toolkit.exploit.service_area import ServiceArea, dump_all_overlays
from hdd_firmware_toolkit.firmware.detection import FirmwareDetection
from hdd_firmware_toolkit.firmware.patcher import FirmwarePatch, FirmwarePatcher
from hdd_firmware_toolkit.firmware.samsung import (
    SamsungFirmwareParser,
    SamsungSection,
    samsung_decode,
)
from hdd_firmware_toolkit.firmware.seagate import SeagateFWLoader, SeagateLODSection
from hdd_firmware_toolkit.firmware.toshiba import ToshibaFirmwareImage, ToshibaFirmwareParser
from hdd_firmware_toolkit.firmware.wd import LZHUFDecoder, WDFirmwareParser, WDSection
from hdd_firmware_toolkit.hw.data_recovery import ReadRetryResult, SATADataRecoveryOps
from hdd_firmware_toolkit.hw.hpa_dco import HPADCOAccess
from hdd_firmware_toolkit.hw.jtag import OpenOCDBridge
from hdd_firmware_toolkit.hw.usb_bridge import USBBridgeInfo, USBToSATABridge
from hdd_firmware_toolkit.nvme.admin import (
    NVMeAdminCmd,
    NVMeAdminPassthrough,
    NVMeDevice,
    NvmePassthruCmd,
)
from hdd_firmware_toolkit.nvme.envme import eNVMeIntegration
from hdd_firmware_toolkit.nvme.ofabrics import NVMeOverFabrics
from hdd_firmware_toolkit.nvme.sandisk import SanDiskNVMeVSC
from hdd_firmware_toolkit.nvme.timing import NVMeTimingSideChannel
from hdd_firmware_toolkit.samsung_mex.aes import SamsungAESInfo
from hdd_firmware_toolkit.samsung_mex.dma import SamsungDMAHelper
from hdd_firmware_toolkit.samsung_mex.gpio import SamsungGPIO
from hdd_firmware_toolkit.samsung_mex.memory_map import SamsungFlashCmd, SamsungMEXMap
from hdd_firmware_toolkit.samsung_mex.ncq import SamsungNCQParser
from hdd_firmware_toolkit.samsung_mex.safe_uart import SamsungSafeUARTClient

__all__ = [
    "ATA_PASS_THROUGH_EX",
    "SAMSUNG_840_EVO_FW_HISTORY",
    "WD_VSC",
    "ASM2362NVMeBridge",
    "ATACmd",
    "ATADevice",
    "ATAError",
    "ATASecurityCommands",
    "FirmwareDetection",
    "FirmwarePatch",
    "FirmwarePatcher",
    "FirmwareUpdateExploit",
    "HPADCOAccess",
    "HotPatchConfig",
    "LZHUFDecoder",
    "NVMeAdminCmd",
    "NVMeAdminPassthrough",
    "NVMeDevice",
    "NVMeOverFabrics",
    "NVMeTimingSideChannel",
    "NvmePassthruCmd",
    "OpenOCDBridge",
    "PatchTemplates",
    "ReadRetryResult",
    "SATADataRecoveryOps",
    "SATCmd",
    "SATLayer",
    "SamsungAESInfo",
    "SamsungDMAHelper",
    "SamsungFirmwareParser",
    "SamsungFlashCmd",
    "SamsungGPIO",
    "SamsungMEXMap",
    "SamsungNCQParser",
    "SamsungSafeUARTClient",
    "SamsungSection",
    "SanDiskNVMeVSC",
    "SeagateFWLoader",
    "SeagateLODSection",
    "ServiceArea",
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
