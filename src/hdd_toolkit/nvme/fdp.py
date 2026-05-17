from __future__ import annotations

import struct
from dataclasses import dataclass, field

from hdd_toolkit.core.models import WriteClass, WriteDeathtimeClassifier
from hdd_toolkit.nvme.admin import NVMeAdminCmd, NVMeAdminPassthrough


@dataclass
class FDPPlacementHint:
    """
    Placement hint for an NVMe Write command under Flexible Data Placement
    (FDP, NVMe TP 4146 / NVMe 2.0).

    The hint is encoded in:
      CDW12 bits [22:20] = dtype (must be 2 for FDP)
      CDW13 bits [15:0]  = dspec (Reclaim Unit Handle ID)

    Sources:
      - NVMe TP 4146: Flexible Data Placement (FDP), Section 3.
      - OCP Cloud SSD Spec v2.5, Section 5: FDP placement requirements.
    """

    nsid: int
    ruh_id: int
    dtype: int = 2
    dspec: int = field(init=False)

    def __post_init__(self) -> None:
        self.dspec = self.ruh_id & 0xFFFF


@dataclass
class RUHDescriptor:
    """Descriptor for a single Reclaim Unit Handle reported by the device."""

    ruh_id: int
    ruh_type: int
    placement_id: int
    ruamw: int


def build_fdp_write_cmd(
    nsid: int,
    slba: int,
    nlb: int,
    ruh_id: int,
    data: bytes = b"",
) -> NVMeAdminCmd:
    """
    Build an NVMe Write command carrying an FDP placement hint.

    CDW12[22:20] = dtype=2 (FDP)
    CDW13[15:0]  = dspec = ruh_id

    Args:
        nsid:   Namespace ID.
        slba:   Starting LBA.
        nlb:    Number of logical blocks minus 1 (NVMe convention).
        ruh_id: Reclaim Unit Handle ID to route writes to.
        data:   Payload bytes (optional for command building).
    """
    cdw10 = slba & 0xFFFFFFFF
    cdw11 = (slba >> 32) & 0xFFFFFFFF
    cdw12 = (nlb & 0xFFFF) | (2 << 20)
    cdw13 = ruh_id & 0xFFFF
    return NVMeAdminCmd(
        opcode=0x01,
        nsid=nsid,
        cdw10=cdw10,
        cdw11=cdw11,
        cdw12=cdw12,
        cdw13=cdw13,
        data_len=len(data),
        data=data,
        is_write=True,
    )


def build_fdp_status_cmd(nsid: int = 0xFFFFFFFF) -> NVMeAdminCmd:
    """
    Build GET LOG PAGE for FDP Configurations log (log 0x70, 512 bytes).

    Log ID 0x70 = Reclaim Unit Handle Usage.

    Sources:
      - NVMe TP 4146, Section 4.3: FDP log pages.
    """
    return NVMeAdminPassthrough.get_log_page(
        log_id=0x70,
        nsid=nsid,
        size=512,
    )


def build_fdp_events_cmd(nsid: int = 0xFFFFFFFF) -> NVMeAdminCmd:
    """
    Build GET LOG PAGE for FDP Events log (log 0x71, 512 bytes).

    Sources:
      - NVMe TP 4146, Section 4.4: FDP Events log.
    """
    return NVMeAdminPassthrough.get_log_page(
        log_id=0x71,
        nsid=nsid,
        size=512,
    )


def parse_fdp_status(data: bytes) -> dict:
    """
    Parse the FDP Reclaim Unit Handle Usage log (log 0x70).

    Layout (from NVMe TP 4146 Section 4.3):
      offset 0: u16 number_of_ruh_descriptors
      offset 2: u16 ruh_descriptor_size (bytes)
      offset 4: reserved (4 bytes)
      offset 8: array of RUH descriptors, each:
        +0  u16 ruh_id
        +2  u8  ruh_type
        +3  u8  placement_id
        +4  u32 ruamw (reclaim unit available media writes, in 512-byte units)

    Args:
        data: raw log page bytes.

    Returns:
        dict with num_ruhs, descriptor_size, and list of RUHDescriptor dicts.
    """
    if len(data) < 8:
        return {"error": "data too short for FDP status log"}
    num_ruhs, desc_size = struct.unpack_from("<HH", data, 0)
    desc_size = desc_size if desc_size >= 8 else 8
    descriptors = []
    for i in range(num_ruhs):
        offset = 8 + i * desc_size
        if offset + 8 > len(data):
            break
        ruh_id, ruh_type, placement_id = struct.unpack_from("<HBB", data, offset)
        (ruamw,) = struct.unpack_from("<I", data, offset + 4)
        descriptors.append(
            {
                "ruh_id": ruh_id,
                "ruh_type": ruh_type,
                "placement_id": placement_id,
                "ruamw": ruamw,
            }
        )
    return {
        "num_ruhs": num_ruhs,
        "descriptor_size": desc_size,
        "descriptors": descriptors,
    }


class RUHAssigner:
    """
    Assigns FDP Reclaim Unit Handle IDs to write streams based on deathtime
    classification from WriteDeathtimeClassifier.

    HOT writes (short deathtime) are directed to hot_ruh_id so they can be
    garbage-collected independently from COLD data, reducing WAF.

    Sources:
      - Lee et al., VLDB vol.19 p.1469 (2026), Section 5: FDP integration.
      - NVMe TP 4146: Flexible Data Placement.
    """

    def __init__(
        self,
        hot_ruh_id: int = 0,
        cold_ruh_id: int = 1,
        deathtime_threshold_ms: float = 60_000.0,
    ) -> None:
        self.hot_ruh_id = hot_ruh_id
        self.cold_ruh_id = cold_ruh_id
        self._classifier = WriteDeathtimeClassifier(deathtime_threshold_ms)
        self._assignment_log: list[dict] = []

    def assign(self, lba: int, size_bytes: int, timestamp: float) -> int:
        """
        Observe a write and return the recommended RUH ID.

        The first time an LBA is seen, it is conservatively assigned to the
        cold RUH.  On subsequent writes (overwrite detected), the previous
        entry is classified and future writes to that LBA use the appropriate
        RUH.

        Returns:
            ruh_id (int): hot_ruh_id or cold_ruh_id.
        """
        cls = self._classifier.observe(lba, size_bytes, timestamp)
        if cls is not None:
            ruh = self.hot_ruh_id if cls == WriteClass.HOT else self.cold_ruh_id
        else:
            ruh = self.cold_ruh_id

        self._assignment_log.append(
            {
                "lba": lba,
                "size_bytes": size_bytes,
                "timestamp": timestamp,
                "ruh_id": ruh,
                "write_class": cls.value if cls is not None else None,
            }
        )
        return ruh

    def build_write_cmd(
        self,
        nsid: int,
        lba: int,
        nlb: int,
        size_bytes: int,
        timestamp: float,
        data: bytes = b"",
    ) -> NVMeAdminCmd:
        """
        Assign a RUH for this LBA and return a fully-built FDP write command.
        """
        ruh_id = self.assign(lba, size_bytes, timestamp)
        return build_fdp_write_cmd(nsid=nsid, slba=lba, nlb=nlb, ruh_id=ruh_id, data=data)

    def assignment_log(self) -> list[dict]:
        """Return the full history of RUH assignments."""
        return list(self._assignment_log)
