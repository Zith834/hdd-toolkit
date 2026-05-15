import struct
from typing import ClassVar

from hdd_toolkit.nvme.admin import NVMeAdminCmd, NVMeAdminPassthrough


class SanDiskNVMeVSC:
    """
    SanDisk and Western Digital NVMe vendor-specific command helpers.

    Provides log page definitions, admin command builders, and feature
    helpers for SanDisk (VID 0x15b7) and WD (VID 0x1c58, 0x1b96) NVMe
    SSDs including the SN7xx consumer/client family (SN740, SN560, SN770)
    and DC SN6xx enterprise family.

    These commands access the vendor-unique log pages (0xC0-0xFF),
    vendor-specific admin opcodes, and vendor-unique features used for
    diagnostics, firmware management, NAND statistics, and debugging.

    Standard NVMe admin commands (identify, fw-dl, get-log-page) are
    in NVMeAdminPassthrough; this class covers the *vendor extensions*
    specific to SanDisk/WD hardware.

    Sources:
      - nvme-cli plugins/wdc/wdc-nvme.c (GPL-2.0, Western Digital):
          Full WDC NVMe plugin with all vendor commands and log parsers
      - nvme-cli plugins/wdc/wdc-nvme.h:
          WDC plugin command registration and capability flags
      - INVESTIGATION.md  -- "eNVMe Platform -- NDSS 2025":
          NVMe firmware exploitation platform context
      - PCIe VID/DID: SanDisk=0x15b7, WDC=0x1c58/0x1b96
    """

    # === PCIe Vendor/Device IDs =============================================
    VID_WDC = 0x1C58
    VID_WDC_2 = 0x1B96
    VID_SANDISK = 0x15B7

    # Known device IDs for SanDisk/WD NVMe SSDs
    # Client/Consumer SN7xx family (includes user's SN740/SN560/SN770)
    DID_SN520: ClassVar[list[int]] = [0x5003, 0x5004, 0x5005]
    DID_SN530: ClassVar[list[int]] = [0x5007, 0x5008, 0x5009, 0x500B, 0x501D]
    DID_SN550: ClassVar[list[int]] = [0x2708]
    DID_SN560: ClassVar[list[int]] = [0x2712, 0x2713, 0x2714]
    DID_SN570: ClassVar[list[int]] = [0x501A]
    DID_SN720: ClassVar[list[int]] = [0x5002]
    DID_SN730: ClassVar[list[int]] = [0x5006]
    DID_SN740: ClassVar[list[int]] = [0x5015, 0x5016, 0x5017, 0x5025]
    DID_SN810: ClassVar[list[int]] = [0x5011]
    DID_SN850X: ClassVar[list[int]] = [0x5030]
    DID_SN7100: ClassVar[list[int]] = [0x5043, 0x5044, 0x5045]
    DID_SN5000: ClassVar[list[int]] = [0x5034, 0x5035, 0x5036, 0x504A]

    # Enterprise DC SN6xx family
    DID_SN630: ClassVar[list[int]] = [0x2200, 0x2201]
    DID_SN640: ClassVar[list[int]] = [0x2400, 0x2401, 0x2402, 0x2404]
    DID_SN650: ClassVar[list[int]] = [0x2700, 0x2701, 0x2702, 0x2720, 0x2721]
    DID_SN655: ClassVar[list[int]] = [0x2722, 0x2723]
    DID_SN840: ClassVar[list[int]] = [0x2300, 0x2500]
    DID_SN860: ClassVar[list[int]] = [0x2730]
    DID_SN861: ClassVar[list[int]] = [0x2750, 0x2751, 0x2752]

    # === Vendor-Specific Log Pages ==========================================
    LOG_C0_EOL_STATUS = 0xC0
    LOG_C1_ADD_SMART = 0xC1
    LOG_C2_DEV_MGMT = 0xC2
    LOG_C3_LATENCY_MON = 0xC3
    LOG_C4_OCP = 0xC4
    LOG_C5_OCP = 0xC5
    LOG_C6_HW_REV = 0xC6
    LOG_C8_DEV_MGMT = 0xC8
    LOG_CA_DEVICE_INFO = 0xCA
    LOG_CB_FW_ACT_HISTORY = 0xCB
    LOG_D0_VU_SMART = 0xD0
    LOG_D1_PCIE_STATS = 0xD1
    LOG_D6 = 0xD6
    LOG_D7 = 0xD7
    LOG_D8 = 0xD8
    LOG_DE = 0xDE
    LOG_F0 = 0xF0
    LOG_F1 = 0xF1
    LOG_F2 = 0xF2
    LOG_FA_DUI = 0xFA
    LOG_FB_NAND_STATS = 0xFB

    # === Vendor-Specific Admin Command Opcodes ==============================
    VU_CAP_DIAG_CMD = 0xC6  # Capture diagnostics (subcmd 0x00)
    VU_DRIVE_RESIZE = 0xCC  # Drive resize (cmd 0x03, subcmd 0x01)
    VU_PCIE_STATS = 0xD1  # PCIe statistics
    VU_CLEAR_PCIE_VUC = 0xD2  # Clear PCIe errors (VUC path)
    VU_CLEAR_ASSERT = 0xD8  # Clear assert dump
    VU_PURGE = 0xDD  # Purge command
    VU_PURGE_MONITOR = 0xDE  # Purge monitor
    VU_CAP_DIAG_HEADER = 0xE6  # Capture diagnostics header
    VU_CAPTURE_DUI = 0xFA  # Capture Device Unit Info
    VU_NAMESPACE_RESIZE = 0xFB  # Namespace resize
    VU_CLEAR_DUMP = 0xFF  # Clear dumps

    # === Feature Identifiers (Get/Set Features) =============================
    FID_CLEAR_PCIE_CORR = 0xC3  # Clear PCIe correctable errors
    FID_LATENCY_MONITOR = 0xC5  # OCP latency monitor feature
    FID_DISABLE_CTLR_TELE = 0xD2  # Disable controller telemetry

    # === SN730-specific Get Log (0xC2 subopcodes) ===========================
    SN730_GET_LOG_OPCODE = 0xC2
    SN730_FULL_LOG_LENGTH = 0x00080009
    SN730_KEY_LOG_LENGTH = 0x00090009
    SN730_COREDUMP_LOG_LENGTH = 0x00120009
    SN730_EXTENDED_LOG_LENGTH = 0x00420009
    SN730_SUB_FULL_LOG = 0x00010009
    SN730_SUB_KEY_LOG = 0x00020009
    SN730_SUB_CORE_LOG = 0x00030009
    SN730_SUB_EXTEND_LOG = 0x00040009
    SN730_LOG_CHUNK_SIZE = 0x1000

    # === Capability Flags ===================================================
    CAP_CAP_DIAG = 0x0000000000000001
    CAP_INTERNAL_LOG = 0x0000000000000002
    CAP_C1_LOG_PAGE = 0x0000000000000004
    CAP_CA_LOG_PAGE = 0x0000000000000008
    CAP_D0_LOG_PAGE = 0x0000000000000010
    CAP_DRIVE_STATUS = 0x0000000000000020
    CAP_CLEAR_ASSERT = 0x0000000000000040
    CAP_CLEAR_PCIE = 0x0000000000000080
    CAP_RESIZE = 0x0000000000000100
    CAP_NAND_STATS = 0x0000000000000200
    CAP_DRIVE_LOG = 0x0000000000000400
    CAP_CRASH_DUMP = 0x0000000000000800
    CAP_PFAIL_DUMP = 0x0000000000001000
    CAP_FW_ACTIVATE_HISTORY = 0x0000000000002000
    CAP_C0_LOG_PAGE = 0x0000000000100000
    CAP_TEMP_STATS = 0x0000000000200000
    CAP_PCIE_STATS = 0x0000000008000000
    CAP_HW_REV_LOG_PAGE = 0x0000000010000000
    CAP_CLOUD_LOG_PAGE = 0x0000000080000000
    CAP_DRIVE_ESSENTIALS = 0x0000000100000000
    CAP_PURGE = 0x0000001000000000
    CAP_DEVICE_WAF = 0x0000010000000000

    # === UUID values for log page routing ===================================
    WDC_UUID = bytes(
        [
            0x2D,
            0xB9,
            0x8C,
            0x52,
            0x0C,
            0x4C,
            0x5A,
            0x15,
            0xAB,
            0xE6,
            0x33,
            0x29,
            0x9A,
            0x70,
            0xDF,
            0xD0,
        ]
    )
    SNDK_UUID = bytes(
        [
            0xDE,
            0x87,
            0xD1,
            0xEB,
            0x72,
            0xC5,
            0x58,
            0x0B,
            0xAD,
            0xD8,
            0x3C,
            0x29,
            0xD1,
            0x23,
            0x7C,
            0x70,
        ]
    )

    # Log page size constants
    LOG_PAGE_512 = 512
    LOG_PAGE_4K = 4096
    LOG_PAGE_C0 = 0x200
    LOG_PAGE_C1 = 0x4000
    LOG_PAGE_C2 = 0x1000
    LOG_PAGE_CA = 0xA0
    LOG_PAGE_D0 = 0x200

    @staticmethod
    def build_get_log_page(log_id: int, size: int = 512, uuid_index: int = 0) -> NVMeAdminCmd:
        """
        Build a GET LOG PAGE command for a vendor-specific log page.

        uuid_index=0 means no UUID routing; set to 1 for WDC_UUID or
        2 for SNDK_UUID when the drive requires UUID-based log routing.
        """
        numdl = (size // 4) - 1
        cdw10 = (log_id & 0xFF) | (numdl << 16)
        if uuid_index:
            cdw10 |= (uuid_index & 0x0F) << 12
        return NVMeAdminCmd(
            opcode=NVMeAdminPassthrough.GET_LOG_PAGE,
            nsid=0xFFFFFFFF,
            cdw10=cdw10,
            data_len=size,
        )

    @staticmethod
    def build_vu_admin_cmd(
        opcode: int,
        cdw10: int = 0,
        cdw11: int = 0,
        cdw12: int = 0,
        cdw13: int = 0,
        cdw14: int = 0,
        cdw15: int = 0,
        data_len: int = 0,
        data: bytes = b"",
        nsid: int = 0,
        is_write: bool = False,
        timeout_ms: int = 5000,
    ) -> NVMeAdminCmd:
        """Build a vendor-specific admin command with arbitrary CDW values."""
        cmd = NVMeAdminCmd(
            opcode=opcode,
            nsid=nsid,
            cdw10=cdw10,
            cdw11=cdw11,
            cdw12=cdw12,
            cdw13=cdw13,
            cdw14=cdw14,
            cdw15=cdw15,
            data_len=data_len,
            data=data,
            is_write=is_write,
            timeout_ms=timeout_ms,
        )
        if data:
            cmd.data_len = len(data)
        return cmd

    @staticmethod
    def build_vu_cap_diag(subcmd: int = 0x00) -> NVMeAdminCmd:
        """
        Build Capture Diagnostics admin command (opcode 0xC6).
        subcmd: 0x00=cap diag, 0x20=drive log, 0x20+sub for crash/pfail dump
        """
        return SanDiskNVMeVSC.build_vu_admin_cmd(
            opcode=SanDiskNVMeVSC.VU_CAP_DIAG_CMD,
            cdw10=subcmd,
        )

    @staticmethod
    def build_purge_cmd() -> NVMeAdminCmd:
        """Build Purge command (opcode 0xDD). Triggers full device purge."""
        return SanDiskNVMeVSC.build_vu_admin_cmd(
            opcode=SanDiskNVMeVSC.VU_PURGE,
            cdw10=0x0000000C,
            timeout_ms=30000,
        )

    @staticmethod
    def build_purge_monitor_cmd() -> NVMeAdminCmd:
        """Build Purge Monitor command (opcode 0xDE). Returns purge status."""
        return SanDiskNVMeVSC.build_vu_admin_cmd(
            opcode=SanDiskNVMeVSC.VU_PURGE_MONITOR,
            cdw10=0x0000000C,
            data_len=0x2F,
            timeout_ms=30000,
        )

    @staticmethod
    def build_drive_resize_cmd(new_size_sectors: int) -> NVMeAdminCmd:
        """
        Build Drive Resize admin command (opcode 0xCC).

        new_size_sectors: target size in 512-byte sectors.
        cdw10 = (cmd=0x03) | (subcmd=0x01 << 8)
        cdw11-12 = new size as u64
        """
        return SanDiskNVMeVSC.build_vu_admin_cmd(
            opcode=SanDiskNVMeVSC.VU_DRIVE_RESIZE,
            cdw10=0x0301,
            cdw11=new_size_sectors & 0xFFFFFFFF,
            cdw12=(new_size_sectors >> 32) & 0xFFFFFFFF,
        )

    @staticmethod
    def build_clear_assert_dump_cmd() -> NVMeAdminCmd:
        """Build Clear Assert Dump (opcode 0xD8, cmd=0x03, subcmd=0x05)."""
        return SanDiskNVMeVSC.build_vu_admin_cmd(
            opcode=SanDiskNVMeVSC.VU_CLEAR_ASSERT,
            cdw10=0x0305,
        )

    @staticmethod
    def build_clear_pcie_errors_vuc_cmd() -> NVMeAdminCmd:
        """Build Clear PCIe errors via VUC (opcode 0xD2)."""
        return SanDiskNVMeVSC.build_vu_admin_cmd(
            opcode=SanDiskNVMeVSC.VU_CLEAR_PCIE_VUC,
            cdw10=0x0104,
        )

    @staticmethod
    def build_clear_fw_act_history_cmd() -> NVMeAdminCmd:
        """Build Clear FW Activate History (opcode 0xC6, cmd=0x23, sub=0x05)."""
        return SanDiskNVMeVSC.build_vu_admin_cmd(
            opcode=SanDiskNVMeVSC.VU_CAP_DIAG_CMD,
            cdw10=0x2305,
        )

    @staticmethod
    def build_get_c0_eol_log() -> NVMeAdminCmd:
        """Build GET LOG PAGE for EOL Status (log 0xC0, 512 bytes)."""
        return SanDiskNVMeVSC.build_get_log_page(
            SanDiskNVMeVSC.LOG_C0_EOL_STATUS, SanDiskNVMeVSC.LOG_PAGE_C0
        )

    @staticmethod
    def build_get_c1_add_smart_log() -> NVMeAdminCmd:
        """Build GET LOG PAGE for Additional SMART (log 0xC1, 16KB)."""
        return SanDiskNVMeVSC.build_get_log_page(
            SanDiskNVMeVSC.LOG_C1_ADD_SMART, SanDiskNVMeVSC.LOG_PAGE_C1
        )

    @staticmethod
    def build_get_c2_dev_mgmt_log() -> NVMeAdminCmd:
        """Build GET LOG PAGE for Device Management (log 0xC2, 4KB)."""
        return SanDiskNVMeVSC.build_get_log_page(
            SanDiskNVMeVSC.LOG_C2_DEV_MGMT, SanDiskNVMeVSC.LOG_PAGE_C2
        )

    @staticmethod
    def build_get_d0_vu_smart_log() -> NVMeAdminCmd:
        """Build GET LOG PAGE for VU SMART (log 0xD0, 512 bytes)."""
        return SanDiskNVMeVSC.build_get_log_page(
            SanDiskNVMeVSC.LOG_D0_VU_SMART, SanDiskNVMeVSC.LOG_PAGE_D0
        )

    @staticmethod
    def build_get_ca_device_info_log() -> NVMeAdminCmd:
        """Build GET LOG PAGE for Device Info (log 0xCA, 160 bytes)."""
        return SanDiskNVMeVSC.build_get_log_page(
            SanDiskNVMeVSC.LOG_CA_DEVICE_INFO, SanDiskNVMeVSC.LOG_PAGE_CA
        )

    @staticmethod
    def build_get_cb_fw_act_history_log() -> NVMeAdminCmd:
        """Build GET LOG PAGE for FW Activate History (log 0xCB, 976 bytes)."""
        return SanDiskNVMeVSC.build_get_log_page(SanDiskNVMeVSC.LOG_CB_FW_ACT_HISTORY, 0x3D0)

    # === Log Page Parsers ===================================================

    @staticmethod
    def parse_c0_eol_log(data: bytes) -> dict:
        """
        Parse 0xC0 EOL Status / SMART Cloud Attributes log page.

        Returns dict with keys:
          realloc_block_count, ecc_rate, write_amp,
          percent_life_remaining, reserved_block_count,
          program_fail_count, erase_fail_count, raw_read_error_rate
        """
        if len(data) < 112:
            return {"error": "data too short", "length": len(data)}
        result = {}
        fields = [
            ("realloc_block_count", 76, 4, "<I"),
            ("ecc_rate", 80, 4, "<I"),
            ("write_amp", 84, 4, "<I"),
            ("percent_life_remaining", 88, 4, "<I"),
            ("reserved_block_count", 92, 4, "<I"),
            ("program_fail_count", 96, 4, "<I"),
            ("erase_fail_count", 100, 4, "<I"),
            ("raw_read_error_rate", 108, 4, "<I"),
        ]
        for name, offset, size, fmt in fields:
            try:
                result[name] = struct.unpack_from(fmt, data, offset)[0]
            except struct.error:
                result[name] = None
        return result

    @staticmethod
    def parse_ca_device_info_log(data: bytes) -> dict:
        """
        Parse 0xCA Device Info log page.

        Returns nand_bytes_written, nand_bytes_read, ecc_errors,
        percent_free_blocks, thermal_throttle_count, etc.
        """
        if len(data) < 120:
            return {"error": "data too short", "length": len(data)}
        result = {}
        fields = [
            ("nand_bytes_written_lo", 0x00, 8, "<Q"),
            ("nand_bytes_written_hi", 0x08, 8, "<Q"),
            ("nand_bytes_read_lo", 0x10, 8, "<Q"),
            ("nand_bytes_read_hi", 0x18, 8, "<Q"),
            ("nand_bad_block_count", 0x20, 8, "<Q"),
            ("uncorrectable_reads", 0x28, 8, "<Q"),
            ("soft_ecc_error_count", 0x30, 8, "<Q"),
            ("e2e_detected_count", 0x38, 4, "<I"),
            ("e2e_corrected_count", 0x3C, 4, "<I"),
            ("data_percent_used", 0x40, 1, "<B"),
            ("data_erase_max", 0x41, 4, "<I"),
            ("data_erase_min", 0x45, 4, "<I"),
            ("refresh_count", 0x49, 8, "<Q"),
            ("program_fail_count", 0x51, 8, "<Q"),
            ("user_erase_fail_count", 0x59, 8, "<Q"),
            ("system_erase_fail_count", 0x61, 8, "<Q"),
            ("thermal_throttle_status", 0x69, 1, "<B"),
            ("thermal_throttle_count", 0x6A, 1, "<B"),
            ("pcie_correctable_errors", 0x6B, 8, "<Q"),
            ("incomplete_shutdowns", 0x73, 4, "<I"),
            ("percent_free_blocks", 0x77, 1, "<B"),
        ]
        for name, offset, size, fmt in fields:
            try:
                result[name] = struct.unpack_from(fmt, data, offset)[0]
            except struct.error:
                result[name] = None
        return result

    @staticmethod
    def parse_d0_vu_smart_log(data: bytes) -> dict:
        """
        Parse 0xD0 Vendor Unique SMART log page.

        Fields: lifetime_realloc_erase_blocks, power_on_hours,
        uecc_count, write_amp_factor, program_fail_count,
        erase_fail_count, die_failure_count, nand_writes, etc.
        """
        if len(data) < 512:
            return {"error": "data too short", "length": len(data)}
        result = {}
        fields = [
            ("smart_log_page_header", 0x00, 4, "<I"),
            ("lifetime_realloc_erase_blocks", 0x04, 4, "<I"),
            ("lifetime_power_on_hours", 0x08, 4, "<I"),
            ("lifetime_uecc_count", 0x0C, 4, "<I"),
            ("lifetime_write_amp_factor", 0x10, 4, "<I"),
            ("trailing_write_amp_factor", 0x14, 4, "<I"),
            ("reserve_erase_block_count", 0x18, 4, "<I"),
            ("lifetime_program_fail_count", 0x1C, 4, "<I"),
            ("lifetime_block_erase_fail", 0x20, 4, "<I"),
            ("lifetime_die_failure_count", 0x24, 4, "<I"),
            ("lifetime_link_rate_downgrades", 0x28, 4, "<I"),
            ("lifetime_clean_shutdowns", 0x2C, 4, "<I"),
            ("lifetime_unclean_shutdowns", 0x30, 4, "<I"),
            ("current_temperature", 0x34, 4, "<I"),
            ("max_recorded_temperature", 0x38, 4, "<I"),
            ("lifetime_retired_block_count", 0x3C, 4, "<I"),
            ("lifetime_read_disturb_realloc", 0x40, 4, "<I"),
            ("lifetime_nand_writes", 0x44, 8, "<Q"),
        ]
        for name, offset, size, fmt in fields:
            try:
                result[name] = struct.unpack_from(fmt, data, offset)[0]
            except struct.error:
                result[name] = None
        return result

    @staticmethod
    def parse_c2_dev_mgmt_log(data: bytes) -> dict:
        """
        Parse 0xC2 Device Management log page (subpage entry format).

        Returns dict keyed by entry_id: marketing_name, log_pages_supported,
        customer_id, thermal_throttle_status, assert_dump_present,
        user_eol_status, format_corrupt_reason.
        """
        if len(data) < 16:
            return {"error": "data too short", "length": len(data)}
        result = {}
        entries = [
            ("marketing_name", 0x07),
            ("log_pages_supported", 0x08),
            ("customer_id", 0x15),
            ("thermal_throttle", 0x18),
            ("assert_dump_present", 0x19),
            ("user_eol_status", 0x1A),
            ("user_eol_state", 0x1C),
            ("system_eol_state", 0x1D),
            ("format_corrupt_reason", 0x1E),
        ]
        offset = 16
        while offset + 12 <= len(data):
            entry_id = struct.unpack_from("<I", data, offset + 4)[0]
            entry_len = struct.unpack_from("<I", data, offset)[0]
            val3 = struct.unpack_from("<I", data, offset + 8)[0]
            label = None
            for name, eid in entries:
                if eid == entry_id:
                    label = name
                    break
            if label:
                result[label] = {
                    "entry_id": entry_id,
                    "value": val3,
                    "length": entry_len,
                }
            offset += 12 + (entry_len - 12 if entry_len > 12 else 0)
        return result

    @staticmethod
    def is_sandisk_nvme(identify_data: bytes) -> bool:
        """Check if IDENTIFY CONTROLLER data matches a SanDisk/WD VID."""
        if len(identify_data) < 4:
            return False
        vid = struct.unpack_from("<H", identify_data, 0)[0]
        return vid in (
            SanDiskNVMeVSC.VID_WDC,
            SanDiskNVMeVSC.VID_WDC_2,
            SanDiskNVMeVSC.VID_SANDISK,
        )

    @staticmethod
    def get_model_family(vid: int, did: int) -> str:
        """Return human-readable model family for a VID/DID pair."""
        if vid == SanDiskNVMeVSC.VID_SANDISK:
            if did in SanDiskNVMeVSC.DID_SN560:
                return "SN560"
            if did in SanDiskNVMeVSC.DID_SN570:
                return "SN570"
            if did in SanDiskNVMeVSC.DID_SN740:
                return "SN740"
            if did in SanDiskNVMeVSC.DID_SN520:
                return "SN520"
            if did in SanDiskNVMeVSC.DID_SN530:
                return "SN530"
            if did in SanDiskNVMeVSC.DID_SN550:
                return "SN550"
            if did in SanDiskNVMeVSC.DID_SN720:
                return "SN720"
            if did in SanDiskNVMeVSC.DID_SN730:
                return "SN730"
            if did in SanDiskNVMeVSC.DID_SN810:
                return "SN810"
            if did in SanDiskNVMeVSC.DID_SN850X:
                return "SN850X"
            if did in SanDiskNVMeVSC.DID_SN7100:
                return "SN7100"
            if did in SanDiskNVMeVSC.DID_SN5000:
                return "SN5000"
        if vid in (SanDiskNVMeVSC.VID_WDC, SanDiskNVMeVSC.VID_WDC_2):
            if did in SanDiskNVMeVSC.DID_SN630:
                return "SN630"
            if did in SanDiskNVMeVSC.DID_SN640:
                return "SN640"
            if did in SanDiskNVMeVSC.DID_SN650:
                return "SN650"
            if did in SanDiskNVMeVSC.DID_SN655:
                return "SN655"
            if did in SanDiskNVMeVSC.DID_SN840:
                return "SN840"
            if did in SanDiskNVMeVSC.DID_SN860:
                return "SN860"
            if did in SanDiskNVMeVSC.DID_SN861:
                return "SN861"
            return "WD DC (unknown)"
        return "Not SanDisk/WD"

    @staticmethod
    def sniff_vendor_log_pages(identify_ctrl_data: bytes) -> list[dict]:
        """
        Given IDENTIFY CONTROLLER data, determine which vendor log
        pages are likely supported based on VID and known capabilities.
        """
        if not SanDiskNVMeVSC.is_sandisk_nvme(identify_ctrl_data):
            return []
        vid = struct.unpack_from("<H", identify_ctrl_data, 0)[0]
        did = struct.unpack_from("<H", identify_ctrl_data, 2)[0]
        family = SanDiskNVMeVSC.get_model_family(vid, did)
        pages = []
        for log_id, name, size in [
            (0xC0, "EOL Status / SMART Cloud Attributes", 0x200),
            (0xC1, "Additional SMART (extended NAND stats)", 0x4000),
            (0xC2, "Device Management", 0x1000),
            (0xCA, "Device Info / Performance", 0xA0),
            (0xCB, "FW Activate History", 0x3D0),
            (0xD0, "VU SMART Log", 0x200),
        ]:
            pages.append(
                {
                    "log_id": log_id,
                    "name": name,
                    "size": size,
                    "likely_supported": True,
                }
            )
        result = {
            "vid": f"0x{vid:04X}",
            "did": f"0x{did:04X}",
            "family": family,
            "vendor": "SanDisk" if vid == SanDiskNVMeVSC.VID_SANDISK else "WDC",
            "log_pages": pages,
        }
        return result
