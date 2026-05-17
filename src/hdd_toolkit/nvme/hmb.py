"""NVMe Host Memory Buffer (HMB) support and attack model."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from hdd_toolkit.nvme.admin import NVMeAdminCmd


# =============================================================================
# NVMe Set Features / Get Features selectors  (NVMe 1.4, Section 5.21.1)
# =============================================================================

NVME_FID_HOST_MEMORY_BUFFER = 0x0D
NVME_SET_FEATURES_OPCODE = 0x09
NVME_GET_FEATURES_OPCODE = 0x0A


# =============================================================================
# HMB descriptor and management
# =============================================================================


@dataclass
class HMBDescriptor:
    """
    A single Host Memory Buffer descriptor entry.

    NVMe 1.4 Section 8.4.2 defines a Host Memory Buffer Descriptor List
    Entry (HMBDLEL).  Each entry describes one contiguous physical memory
    region that the host makes available to the NVMe controller.

    The controller uses these regions for internal caching, FTL tables,
    write buffers, and L2P mapping tables.  A malicious or compromised
    controller can read/write these regions directly via DMA.

    Entry layout (NVMe 1.4, Section 8.4.2, Table 106):
      offset  0  8 bytes BADD  -- base DMA address (4-KiB aligned)
      offset  8  4 bytes BSIZE -- buffer size in 4-KiB units
      offset 12  4 bytes reserved

    Sources:
      - NVMe Base Specification 1.4, Section 8.4.2: HMB Descriptor List Entry.
      - NVMe Base Specification 2.0, Section 8.5: Host Memory Buffer.
    """

    base_address: int = 0
    size_4k: int = 0

    @property
    def size_bytes(self) -> int:
        return self.size_4k * 4096

    def pack(self) -> bytes:
        """Serialize to 16-byte wire format."""
        return struct.pack("<QII", self.base_address, self.size_4k, 0)

    @classmethod
    def unpack(cls, data: bytes) -> "HMBDescriptor":
        """Parse from 16-byte wire format."""
        if len(data) < 16:
            return cls()
        base, size_4k, _ = struct.unpack_from("<QII", data, 0)
        return cls(base_address=base, size_4k=size_4k)


@dataclass
class HMBAllocation:
    """
    A set of HMB descriptor entries representing one HMB allocation.

    Sources:
      - NVMe Base Specification 1.4, Section 8.4.
    """

    descriptors: list[HMBDescriptor] = field(default_factory=list)

    @property
    def total_size_bytes(self) -> int:
        return sum(d.size_bytes for d in self.descriptors)

    @property
    def descriptor_count(self) -> int:
        return len(self.descriptors)

    def pack_descriptor_list(self) -> bytes:
        """Serialize all descriptors to a contiguous byte array."""
        return b"".join(d.pack() for d in self.descriptors)

    @classmethod
    def from_descriptor_list(cls, data: bytes) -> "HMBAllocation":
        """Parse all descriptors from a flat byte array."""
        descriptors = []
        for i in range(0, len(data) - 15, 16):
            descriptors.append(HMBDescriptor.unpack(data[i : i + 16]))
        return cls(descriptors=descriptors)


# =============================================================================
# NVMe admin command builders
# =============================================================================


def build_hmb_enable_cmd(
    allocation: HMBAllocation,
    descriptor_list_addr: int,
    mr: bool = False,
) -> NVMeAdminCmd:
    """
    Build SET FEATURES (FID 0x0D) to enable Host Memory Buffer.

    CDW10[31:0]:
      bits[31:8] = FID (0x0D) -- Feature Identifier
      bits[7:0]  = reserved
    CDW11:
      bit 1 = MR (Memory Return -- controller returns buffer on disable)
      bit 0 = EHM (Enable Host Memory)
    CDW12[31:0]: HSIZE -- total HMB size in 4-KiB units
    CDW13[31:0]: HMDLAL -- descriptor list base address low 32 bits
    CDW14[31:0]: HMDLAU -- descriptor list base address high 32 bits
    CDW15[31:0]: HMDLEC -- descriptor list entry count

    Args:
        allocation: HMBAllocation describing the host memory regions.
        descriptor_list_addr: Physical address of the descriptor list in host memory.
        mr: Memory Return bit.  When True the controller copies HMB data
            back to host before disabling (preserves cached data).

    Returns:
        NVMeAdminCmd for SET FEATURES (HMB enable).

    Sources:
      - NVMe Base Specification 1.4, Section 5.21.1.13: Host Memory Buffer.
    """
    ehm = 0x01
    mr_bit = 0x02 if mr else 0x00
    cdw11 = ehm | mr_bit
    hsize = allocation.total_size_bytes // 4096
    hmdlal = descriptor_list_addr & 0xFFFFFFFF
    hmdlau = (descriptor_list_addr >> 32) & 0xFFFFFFFF
    hmdlec = allocation.descriptor_count

    return NVMeAdminCmd(
        opcode=NVME_SET_FEATURES_OPCODE,
        nsid=0,
        cdw10=NVME_FID_HOST_MEMORY_BUFFER,
        cdw11=cdw11,
        cdw12=hsize,
        cdw13=hmdlal,
        cdw14=hmdlau,
        cdw15=hmdlec,
        data_len=0,
    )


def build_hmb_disable_cmd(mr: bool = False) -> NVMeAdminCmd:
    """
    Build SET FEATURES (FID 0x0D) to disable Host Memory Buffer.

    EHM bit is cleared, signalling the controller to stop using HMB.

    Args:
        mr: If True, request that the controller flush cached data
            back to the host memory before stopping.

    Returns:
        NVMeAdminCmd for SET FEATURES (HMB disable).

    Sources:
      - NVMe Base Specification 1.4, Section 5.21.1.13.
    """
    mr_bit = 0x02 if mr else 0x00
    return NVMeAdminCmd(
        opcode=NVME_SET_FEATURES_OPCODE,
        nsid=0,
        cdw10=NVME_FID_HOST_MEMORY_BUFFER,
        cdw11=mr_bit,
        data_len=0,
    )


def build_hmb_get_cmd() -> NVMeAdminCmd:
    """
    Build GET FEATURES (FID 0x0D) to query current HMB configuration.

    The completion queue entry DW0 returns:
      bit 1 = MR
      bit 0 = EHM (enabled)
    DW1 returns HSIZE.

    Returns:
        NVMeAdminCmd for GET FEATURES (HMB).

    Sources:
      - NVMe Base Specification 1.4, Section 5.21.1.13.
    """
    return NVMeAdminCmd(
        opcode=NVME_GET_FEATURES_OPCODE,
        nsid=0,
        cdw10=NVME_FID_HOST_MEMORY_BUFFER,
        data_len=0,
    )


def parse_hmb_caps_from_identify(identify_data: bytes) -> dict:
    """
    Extract HMB-related capability fields from Identify Controller data.

    Relevant Identify Controller fields (NVMe 1.4, Section 5.15.2):
      offset 272  u32 HMMIN  -- Host Memory Minimum Size (4-KiB units)
      offset 276  u64 HMPRE  -- Host Memory Preferred Size (4-KiB units)

    Args:
        identify_data: 4096-byte Identify Controller response.

    Returns:
        Dict with hmmin_bytes, hmpre_bytes, hmb_supported.

    Sources:
      - NVMe Base Specification 1.4, Section 5.15.2.3: HMMIN and HMPRE.
    """
    if len(identify_data) < 284:
        return {"hmb_supported": False, "hmmin_bytes": 0, "hmpre_bytes": 0}
    hmmin = struct.unpack_from("<I", identify_data, 272)[0]
    hmpre = struct.unpack_from("<Q", identify_data, 276)[0]
    return {
        "hmb_supported": hmmin > 0,
        "hmmin_bytes": hmmin * 4096,
        "hmpre_bytes": hmpre * 4096,
        "hmmin_4k": hmmin,
        "hmpre_4k": hmpre,
    }


# =============================================================================
# Attack model
# =============================================================================


class HMBAttackModel:
    """
    Attack surface model for NVMe Host Memory Buffer.

    When a host enables HMB, it grants the NVMe controller direct read/write
    access to specified regions of host DRAM via DMA.  A compromised or
    malicious controller firmware can abuse this in several ways:

    Read Beyond Descriptor
    ----------------------
    A controller firmware bug or intentional backdoor can read beyond the
    descriptor-specified size if the DMA engine does not enforce strict
    per-descriptor limits.  This is analogous to the eNVMe DMA attack but
    uses the legitimate HMB DMA path rather than a malicious PRP/SGL.

    Descriptor Address Manipulation
    --------------------------------
    If the HMB descriptor list itself resides in a predictable location
    (e.g., fixed kernel virtual-to-physical mapping), a firmware implant
    can parse the list, discover all host memory regions, and selectively
    read/write data structures such as page tables or credential caches.

    Persistent Data Leakage
    -------------------------
    Unlike standard DMA (which requires the OS DMA API), HMB regions are
    explicitly registered by the driver and pinned in DRAM.  A drive implant
    that records LBA -> HMB region mappings can exfiltrate recently written
    host data on next power-on, surviving a graceful shutdown.

    Memory Probing via Access Timing
    ---------------------------------
    The controller can infer host memory layout from HMB access latencies
    (similar to eNVMe timing attacks) because the DMA engine touches real
    host cache lines.  This can be used to locate high-value data structures
    without scanning the full address space.

    Sources:
      - Dai Zovi, "Hardware Backdoors in x86 CPUs" (DEF CON 20, 2012):
          DMA-capable device as a memory read primitive.
      - NVMe Base Specification 1.4, Section 8.4: Host Memory Buffer.
      - "Project Zero" blog (2019): PCIe DMA as an attack surface in
          Thunderbolt / direct DMA scenarios.
      - Frisk, "Direct Memory Access Attacks" (DEF CON 24, 2016).
    """

    def __init__(self, allocation: HMBAllocation):
        self.allocation = allocation

    def enumerate_regions(self) -> list[dict]:
        """
        Enumerate all host memory regions registered in the HMB allocation.

        Returns:
            List of dicts with base_address, size_bytes, end_address fields.
        """
        regions = []
        for desc in self.allocation.descriptors:
            regions.append(
                {
                    "base_address": desc.base_address,
                    "size_bytes": desc.size_bytes,
                    "end_address": desc.base_address + desc.size_bytes - 1,
                    "size_4k_pages": desc.size_4k,
                }
            )
        return regions

    def estimate_overflow_range(self, overflow_pages: int = 1) -> list[dict]:
        """
        Estimate host memory ranges accessible if the controller reads
        `overflow_pages` 4-KiB pages beyond each descriptor boundary.

        This models the "read-beyond-descriptor" attack.

        Args:
            overflow_pages: Number of 4-KiB pages the controller reads past
                            each descriptor end address.

        Returns:
            List of dicts describing the overflow range per descriptor.
        """
        result = []
        for desc in self.allocation.descriptors:
            overflow_start = desc.base_address + desc.size_bytes
            overflow_end = overflow_start + overflow_pages * 4096 - 1
            result.append(
                {
                    "descriptor_end": desc.base_address + desc.size_bytes - 1,
                    "overflow_start": overflow_start,
                    "overflow_end": overflow_end,
                    "overflow_bytes": overflow_pages * 4096,
                }
            )
        return result

    def attack_report(self) -> dict:
        """
        Produce a summary attack surface report for the registered HMB.

        Returns:
            Dict with total_size, region_count, regions, and risk flags.
        """
        total = self.allocation.total_size_bytes
        regions = self.enumerate_regions()
        overflow = self.estimate_overflow_range(overflow_pages=1)
        flags: list[str] = []

        if total >= 64 * 1024 * 1024:
            flags.append("large_hmb_over_64mb")
        if len(regions) > 8:
            flags.append("many_descriptor_entries")

        for r in regions:
            if r["base_address"] < 0x10_0000:
                flags.append("low_memory_region_below_1mb")
                break

        return {
            "total_size_bytes": total,
            "total_size_mb": total / (1024 * 1024),
            "region_count": len(regions),
            "regions": regions,
            "overflow_model": overflow,
            "risk_flags": flags,
            "risk_level": "high" if flags else "medium",
        }
