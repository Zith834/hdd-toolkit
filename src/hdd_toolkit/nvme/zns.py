from __future__ import annotations

import struct
from dataclasses import dataclass

from hdd_toolkit.nvme.admin import NVMeAdminCmd
from hdd_toolkit.nvme.waf import WAFMeter


class ZoneAction:
    """
    Zone Management Send action codes (NVMe ZNS TP 4053 / NVMe 2.0).

    Sources:
      - NVMe ZNS TP 4053, Section 2.2: Zone Management Send.
    """

    CLOSE = 0x01
    FINISH = 0x02
    OPEN = 0x03
    RESET = 0x04
    OFFLINE = 0x05


class ZoneReportAction:
    """Report Zones selection filter codes."""

    ALL = 0x00
    EMPTY = 0x01
    OPEN_IMPLICIT = 0x02
    OPEN_EXPLICIT = 0x03
    CLOSED = 0x04
    FULL = 0x05
    READ_ONLY = 0x06
    OFFLINE = 0x07


@dataclass
class ZNSZoneDescriptor:
    """
    Parsed descriptor for a single ZNS zone.

    Fields match the Zone Descriptor format returned by Report Zones
    (NVMe ZNS TP 4053 Section 2.3).

    Sources:
      - NVMe ZNS TP 4053, Section 2.3: Zone Descriptor format.
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 5.3: ZNS sweep.
    """

    zone_start_lba: int
    zone_capacity: int
    write_pointer: int
    zone_state: int
    zone_type: int = 2

    @property
    def is_full(self) -> bool:
        return self.zone_state == 0x0E

    @property
    def is_empty(self) -> bool:
        return self.zone_state == 0x01


def build_zone_mgmt_send(
    nsid: int,
    slba: int,
    action: int,
    select_all: bool = False,
) -> NVMeAdminCmd:
    """
    Build a Zone Management Send command (NVMe I/O opcode 0x79).

    CDW10[31:0] = SLBA low 32 bits
    CDW11[31:0] = SLBA high 32 bits
    CDW13[3:0]  = action
    CDW13[8]    = select_all

    Sources:
      - NVMe ZNS TP 4053, Section 2.2.
    """
    cdw13 = (action & 0x0F) | (int(select_all) << 8)
    return NVMeAdminCmd(
        opcode=0x79,
        nsid=nsid,
        cdw10=slba & 0xFFFFFFFF,
        cdw11=(slba >> 32) & 0xFFFFFFFF,
        cdw13=cdw13,
        data_len=0,
    )


def build_zone_mgmt_recv(
    nsid: int,
    slba: int,
    action: int = ZoneReportAction.ALL,
    count: int = 1,
    data_len: int = 4096,
) -> NVMeAdminCmd:
    """
    Build a Zone Management Receive command (NVMe I/O opcode 0x7A).

    CDW10[31:0] = SLBA low 32 bits
    CDW11[31:0] = SLBA high 32 bits
    CDW12[31:0] = ZRMSRL (number of dwords to return, 0-based)
    CDW13[7:0]  = action (ZRA)

    Sources:
      - NVMe ZNS TP 4053, Section 2.3.
    """
    numd = (data_len // 4) - 1
    return NVMeAdminCmd(
        opcode=0x7A,
        nsid=nsid,
        cdw10=slba & 0xFFFFFFFF,
        cdw11=(slba >> 32) & 0xFFFFFFFF,
        cdw12=numd & 0xFFFFFFFF,
        cdw13=action & 0xFF,
        data_len=data_len,
    )


def build_zone_append(
    nsid: int,
    zone_slba: int,
    nlb: int,
    data: bytes = b"",
) -> NVMeAdminCmd:
    """
    Build a Zone Append command (NVMe I/O opcode 0x7D).

    CDW10[31:0] = zone SLBA low 32 bits
    CDW11[31:0] = zone SLBA high 32 bits
    CDW12[15:0] = NLB (number of logical blocks minus 1)

    The write pointer advances automatically; the device returns the LBA
    in the completion queue entry.

    Sources:
      - NVMe ZNS TP 4053, Section 2.1: Zone Append.
    """
    return NVMeAdminCmd(
        opcode=0x7D,
        nsid=nsid,
        cdw10=zone_slba & 0xFFFFFFFF,
        cdw11=(zone_slba >> 32) & 0xFFFFFFFF,
        cdw12=nlb & 0xFFFF,
        data_len=len(data),
        data=data,
        is_write=True,
    )


def parse_zone_report(data: bytes) -> list[ZNSZoneDescriptor]:
    """
    Parse the Report Zones response buffer into ZNSZoneDescriptor objects.

    Report Zones header (16 bytes):
      offset 0: u64 number_of_zones
      offset 8: reserved (8 bytes)
    Each Zone Descriptor (64 bytes):
      offset 0:  u8  zone_type
      offset 1:  u8  zone_state (bits [7:4])
      offset 8:  u64 zone_capacity (LBA count)
      offset 16: u64 zone_start_lba
      offset 24: u64 write_pointer_lba
      offset 32: reserved (32 bytes)

    Sources:
      - NVMe ZNS TP 4053, Section 2.3.3: Report Zones data structure.
    """
    if len(data) < 16:
        return []
    (num_zones,) = struct.unpack_from("<Q", data, 0)
    zones = []
    zone_desc_size = 64
    for i in range(num_zones):
        offset = 16 + i * zone_desc_size
        if offset + zone_desc_size > len(data):
            break
        zone_type = data[offset] & 0x0F
        zone_state = (data[offset + 1] >> 4) & 0x0F
        (zone_capacity,) = struct.unpack_from("<Q", data, offset + 8)
        (zone_start_lba,) = struct.unpack_from("<Q", data, offset + 16)
        (write_pointer,) = struct.unpack_from("<Q", data, offset + 24)
        zones.append(
            ZNSZoneDescriptor(
                zone_start_lba=zone_start_lba,
                zone_capacity=zone_capacity,
                write_pointer=write_pointer,
                zone_state=zone_state,
                zone_type=zone_type,
            )
        )
    return zones


class ZNSSweeper:
    """
    Iterates ZNS zones to infer the GC stripe (erase unit) size via WAF
    inflection analysis.

    Algorithm (Lee et al. VLDB vol.19 p.1469 Section 5.3):
      1. Report all zones to get their sizes.
      2. For each candidate write size, fill N zones with zone-append writes
         of that size, snapshot WAF before and after, record delta WAF.
      3. The candidate block size where WAF drops sharply corresponds to
         writes that are aligned to the GC stripe boundary.

    In a real deployment *snap_func* and *fill_func* make ioctl calls;
    in testing they accept callable mocks.

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 5.3.
      - NVMe ZNS TP 4053.
    """

    def __init__(
        self,
        nsid: int = 1,
        zone_size_lba: int = 2048,
        lba_size: int = 4096,
    ) -> None:
        self.nsid = nsid
        self.zone_size_lba = zone_size_lba
        self.lba_size = lba_size
        self._meter = WAFMeter()

    def sweep(
        self,
        snap_func,
        write_sizes: list[int] | None = None,
        num_zones: int = 4,
    ) -> list[dict]:
        """
        Perform a GC-inference sweep across write sizes.

        Args:
            snap_func: callable(write_size: int) -> (before_buf: bytes, after_buf: bytes)
                       where each buf is a 512-byte OCP C1 log snapshot.
            write_sizes: list of write sizes in bytes to test.
            num_zones: number of zones to fill per measurement step.

        Returns:
            List of dicts: {write_size, waf, nand_delta, host_delta}.
        """
        if write_sizes is None:
            write_sizes = [4096, 8192, 16384, 32768, 65536, 131072]

        results = []
        for ws in sorted(write_sizes):
            before_buf, after_buf = snap_func(ws)
            self._meter.snapshot_before(before_buf)
            self._meter.snapshot_after(after_buf)
            delta = self._meter.delta_waf()
            results.append(
                {
                    "write_size": ws,
                    "waf": delta.get("waf", 0.0),
                    "nand_delta": delta.get("delta_nand_written", 0),
                    "host_delta": delta.get("delta_host_written", 0),
                }
            )
        return results

    def estimate_gc_unit(self, sweep_results: list[dict]) -> int:
        """
        Estimate GC stripe size from sweep results.

        Returns the smallest write_size at which WAF drops below 1.1
        (near-unity WAF indicating GC-aligned writes), or 0 if none found.
        """
        for point in sorted(sweep_results, key=lambda p: p["write_size"]):
            if 0 < point["waf"] < 1.1:
                return point["write_size"]
        return 0
