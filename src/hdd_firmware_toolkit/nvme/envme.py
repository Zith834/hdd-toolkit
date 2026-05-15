import struct
from typing import ClassVar


class eNVMeIntegration:  # noqa: N801
    """
    Integration with the eNVMe open-source NVMe firmware platform.
    eNVMe runs a full Linux instance on the NVMe SSD's RK3588 controller,
    enabling PCIe DMA attacks, host memory scanning, and kernel module
    injection directly from within the SSD.

    Attack vectors supported:
      - PCI DMA: Scan host RAM, inject kernel modules from SSD firmware
      - IOMMU bypass: Techniques to circumvent IOMMU protections
      - File-system manipulation: Modify files from within the storage device
      - Remote activation: Trigger via specific write patterns to the SSD
      - PCILeech integration: DMA attack software compatibility

    Sources:
      - INVESTIGATION.md  -- "eNVMe -- arXiv 2411.00439, NDSS 2025":
          Full eNVMe platform reference: DMA attacks, IOMMU bypass, RK3588
      - INVESTIGATION.md  -- "github.com/rick-heig/eNVMe":
          Open-source eNVMe implementation with PCILeech integration
      - INVESTIGATION.md  -- "NVMe FTL Corruption Recovery (2026)":
          ASM2362 XRAM injection -- TLP doorbell for NVMe admin queue
    """

    # eNVMe platform constants (from RK3588 reference)
    RK3588_PCIE_BAR0 = 0xFE000000
    RK3588_DMA_BASE = 0xFE0A0000
    MAX_DMA_TRANSFER = 0x10000  # 64KB per DMA operation
    DEFAULT_NSID = 1
    PCILeech_SUPPORTED = True

    # Known eNVMe-compatible controllers
    COMPATIBLE_CTRLRS: ClassVar[list[str]] = [
        "RK3588",
        "CM3588",
        "SM2263",
        "SM2263XT",
        "SM2258",
        "SM2259",
        "PS5016",
        "PS5018",
    ]

    @staticmethod
    def build_dma_attack_cmd(host_phys_addr: int, size: int, direction: str = "read") -> dict:
        """
        Model a PCIe DMA attack command from the SSD controller.
        Returns a descriptor that maps host physical memory for direct
        read/write from the NVMe firmware context.
        """
        if size > eNVMeIntegration.MAX_DMA_TRANSFER:
            size = eNVMeIntegration.MAX_DMA_TRANSFER
        return {
            "host_phys_addr": host_phys_addr,
            "size": size,
            "direction": direction,
            "target_sq": 0,  # Submission queue to inject
            "dma_engine": "RK3588",
            "requires_bar0": host_phys_addr < 0x100000000,
            "description": (
                f"{'Read' if direction == 'read' else 'Write'} "
                f"{size} bytes at host phys 0x{host_phys_addr:X}"
            ),
        }

    @staticmethod
    def scan_host_memory(
        pattern: bytes = b"\x00", chunk_size: int = 4096, max_pages: int = 1024
    ) -> dict:
        """
        Model host memory scanning via PCIe DMA from the SSD.
        In real eNVMe deployment this scans for sensitive data in host RAM.
        """
        total_bytes = chunk_size * max_pages
        host_regions = [
            {"start": 0x100000, "label": "kernel_low", "size": 0x100000},
            {"start": 0x20000000, "label": "kernel_high", "size": 0x8000000},
            {"start": 0x100000000, "label": "user_space", "size": 0x20000000},
        ]
        return {
            "scan_chunk": chunk_size,
            "max_pages": max_pages,
            "total_scan_bytes": total_bytes,
            "host_regions": host_regions,
            "requires_iommu_bypass": True,
            "description": (
                f"DMA scan up to {total_bytes // 1024} KB of host RAM in {chunk_size}-byte chunks"
            ),
            "iommu_bypass_method": "disable_translation_via_pcie_cfg",
        }

    @staticmethod
    def build_kernel_module_injection(module_data: bytes, target_addr: int = 0) -> dict:
        """
        Model kernel module injection from SSD firmware into host OS.
        In real eNVMe: write module data to host kernel memory via DMA,
        then trigger module loading via modifying kernel module lists.
        """
        return {
            "module_size": len(module_data),
            "target_addr": target_addr,
            "method": "dma_write_kernel_mem",
            "activation": "modify_module_list_or_syscall_table",
            "ioOmu_protection": False,
            "risk_level": "critical",
        }

    @staticmethod
    def detect_platform_compatibility(identify_ctrlr_data: bytes) -> dict:
        """
        Check NVMe Identify Controller data for features that enable
        eNVMe-style exploitation: large PRP lists, SGL support,
        controller memory buffer, SR-IOV capability.
        """
        if len(identify_ctrlr_data) < 4096:
            return {"compatible": False, "error": "identify data too short"}
        words = list(struct.unpack_from("<2048H", identify_ctrlr_data, 0))
        # Check for key capabilities
        sgl_support = bool(words[25] & 0xF)
        cmb_support = bool(words[29] & 0x01)
        sriov_support = bool(words[31] & 0x01)
        max_data_transfer = words[77]  # MDTS in units of min page size
        compatible_ctrlr = "unknown"
        # Try to identify controller via vendor-specific words
        return {
            "sgl_supported": sgl_support,
            "cmb_supported": cmb_support,
            "sriov_supported": sriov_support,
            "mdts": max_data_transfer,
            "compatible": True,
            "compatible_ctrlr": compatible_ctrlr,
            "notes": (
                "eNVMe-style DMA attack possible"
                if sgl_support or cmb_support
                else "eNVMe may need IOMMU bypass"
            ),
        }

    @staticmethod
    def remote_activation_pattern(magic_bytes: bytes) -> bytes:
        """
        Generate a write pattern that triggers remote activation.
        eNVMe uses specific write sequences to activate attack payloads
        without physical access or host software installation.
        """
        if len(magic_bytes) < 4:
            magic_bytes = b"eNVM"
        pattern = b"\x00" * 512
        pattern = magic_bytes.ljust(8, b"\x00") + pattern[8:]
        return pattern
