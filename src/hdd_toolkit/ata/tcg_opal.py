"""TCG Opal / SED (Self-Encrypting Drive) protocol layer."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

from hdd_toolkit.ata.commands import ATADevice


# =============================================================================
# ATA IF_SEND / IF_RECV command codes
# =============================================================================

ATA_IF_RECV = 0x5C
ATA_IF_SEND = 0x5E

TRUSTED_SECURITY_PROTOCOL_TCG = 0x01
TCG_LEVEL0_COMID = 0x0001


# =============================================================================
# TCG feature codes  (TCG Storage Architecture Core Specification, Table 17)
# =============================================================================


class TCGFeatureCode(IntEnum):
    """
    TCG Level 0 Discovery feature codes.

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01, Table 17.
      - sedutil source: Common/DtaStructures.h (feature code constants).
    """

    TPER = 0x0001
    LOCKING = 0x0002
    GEOMETRY = 0x0003
    ENTERPRISE = 0x0100
    OPAL_V100 = 0x0200
    SINGLE_USER_MODE = 0x0201
    DATASTORE = 0x0202
    OPAL_V200 = 0x0203
    BLOCK_SID_AUTH = 0x0302
    OPALITE = 0x0304
    PYRITE_V100 = 0x0307
    PYRITE_V200 = 0x0308
    RUBY_V100 = 0x030B
    DATA_REMOVAL = 0x0402


# =============================================================================
# Feature descriptor dataclasses
# =============================================================================


@dataclass
class TCGTPerFeature:
    """
    TPer Feature descriptor (feature code 0x0001).

    Flags indicate which communication capabilities the TPer supports.

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01, Section 3.3.2.
    """

    sync: bool = False
    async_: bool = False
    ack_nack: bool = False
    buffer_mgmt: bool = False
    streaming: bool = False
    com_id_mgmt: bool = False


@dataclass
class TCGLockingFeature:
    """
    Locking Feature descriptor (feature code 0x0002).

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01, Section 3.3.3.
    """

    locking_supported: bool = False
    locking_enabled: bool = False
    locked: bool = False
    media_encryption: bool = False
    mbr_enabled: bool = False
    mbr_done: bool = False


@dataclass
class TCGGeometryFeature:
    """
    Geometry Reporting Feature descriptor (feature code 0x0003).

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01, Section 3.3.4.
    """

    align: bool = False
    logical_block_size: int = 512
    alignment_granularity: int = 0
    lowest_aligned_lba: int = 0


@dataclass
class TCGOpalV200Feature:
    """
    Opal SSC 2.0 Feature descriptor (feature code 0x0203).

    Sources:
      - TCG Opal SSC 2.01, Section 3.3.6.
    """

    base_com_id: int = 0
    num_com_ids: int = 0
    range_crossing: bool = False
    num_locking_admin_auth: int = 0
    num_locking_user_auth: int = 0
    initial_pin: int = 0x00
    reverted_pin: int = 0x00


@dataclass
class TCGDiscovery0:
    """
    Parsed Level 0 Discovery response.

    Level 0 Discovery (L0D) is retrieved by sending ATA IF_RECV with
    security protocol 0x01 and ComID 0x0001.  The 512-byte response
    contains a 48-byte header followed by a packed list of feature
    descriptors, each with a 2-byte feature code, a 1-byte
    version/reserved nibble, a 1-byte length, and feature-specific data.

    This is the first step in any TCG Opal interaction:
      1. Issue IF_RECV (0x5C) / TRUSTED RECEIVE to get L0D.
      2. Parse feature codes to discover which SSC the drive supports
         (Enterprise, Opal 1.0, Opal 2.0, Pyrite, Opalite, Ruby).
      3. Open a session using the BaseComID reported in the SSC descriptor.
      4. Issue method calls (StartSession, Authenticate, Revert, etc.)
         wrapped in ComPacket/Packet/SubPacket.

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01, Section 3.3.
      - TCG Opal SSC Feature Set 2.01, Section 3.
      - sedutil v1.15: Common/DtaStructures.h, LinuxNVMe/DtaDevLinuxNVMe.cpp.
      - Boteanu & Bhargava, "Bypassing Self-Encrypting Drives" (BHEU 2015):
          L0D as the first step in SED enumeration.
    """

    header_length: int = 0
    revision: int = 0
    tper: TCGTPerFeature | None = None
    locking: TCGLockingFeature | None = None
    geometry: TCGGeometryFeature | None = None
    opal_v200: TCGOpalV200Feature | None = None
    has_enterprise: bool = False
    has_opal_v100: bool = False
    has_single_user: bool = False
    has_datastore: bool = False
    has_block_sid: bool = False
    has_opalite: bool = False
    has_pyrite_v100: bool = False
    has_pyrite_v200: bool = False
    has_ruby: bool = False
    has_data_removal: bool = False
    base_com_id: int = 0
    raw_features: list[dict] = field(default_factory=list)

    @property
    def is_opal(self) -> bool:
        return self.opal_v200 is not None or self.has_opal_v100

    @property
    def is_enterprise(self) -> bool:
        return self.has_enterprise

    @property
    def ssc_name(self) -> str:
        if self.opal_v200 is not None:
            return "Opal 2.0"
        if self.has_opal_v100:
            return "Opal 1.0"
        if self.has_enterprise:
            return "Enterprise"
        if self.has_pyrite_v200:
            return "Pyrite 2.0"
        if self.has_pyrite_v100:
            return "Pyrite 1.0"
        if self.has_opalite:
            return "Opalite"
        if self.has_ruby:
            return "Ruby 1.0"
        return "unknown"


# =============================================================================
# Discovery 0 parser
# =============================================================================


class TCGDiscovery0Parser:
    """
    Parse a Level 0 Discovery response buffer.

    The buffer is 512 bytes returned by ATA IF_RECV / TRUSTED RECEIVE
    (protocol 0x01, ComID 0x0001).  The first 48 bytes are a header;
    the remainder is a packed list of feature descriptors.

    Header layout (all big-endian):
      offset 0  u32  length (bytes that follow, not including this field)
      offset 4  u32  revision
      offset 8  reserved (8 bytes)
      offset 16 vendor-specific (32 bytes)

    Feature descriptor layout:
      offset 0  u16  feature code
      offset 2  u8   version[7:4] | reserved[3:0]
      offset 3  u8   length (bytes that follow, not including the 4-byte header)
      offset 4  <feature-specific bytes>

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01, Section 3.3.
    """

    HEADER_SIZE = 48

    @classmethod
    def parse(cls, data: bytes) -> TCGDiscovery0:
        """
        Parse a 512-byte Level 0 Discovery response.

        Args:
            data: Raw 512-byte IF_RECV response.

        Returns:
            TCGDiscovery0 with all recognised feature descriptors populated.
        """
        if len(data) < cls.HEADER_SIZE:
            return TCGDiscovery0()

        length, revision = struct.unpack_from(">II", data, 0)
        result = TCGDiscovery0(header_length=length, revision=revision)

        offset = cls.HEADER_SIZE
        end = min(length + 4, len(data))

        while offset + 4 <= end:
            feat_code, ver_res, feat_len = struct.unpack_from(">HBB", data, offset)
            feat_data = data[offset + 4 : offset + 4 + feat_len]
            result.raw_features.append(
                {"code": feat_code, "version": (ver_res >> 4) & 0xF, "data": feat_data}
            )
            cls._dispatch(result, feat_code, feat_data)
            offset += 4 + feat_len

        return result

    @classmethod
    def _dispatch(cls, result: TCGDiscovery0, code: int, data: bytes) -> None:
        if code == TCGFeatureCode.TPER:
            cls._parse_tper(result, data)
        elif code == TCGFeatureCode.LOCKING:
            cls._parse_locking(result, data)
        elif code == TCGFeatureCode.GEOMETRY:
            cls._parse_geometry(result, data)
        elif code == TCGFeatureCode.OPAL_V200:
            cls._parse_opal_v200(result, data)
        elif code == TCGFeatureCode.ENTERPRISE:
            result.has_enterprise = True
            if len(data) >= 4:
                result.base_com_id = struct.unpack_from(">H", data, 0)[0]
        elif code == TCGFeatureCode.OPAL_V100:
            result.has_opal_v100 = True
            if len(data) >= 2:
                result.base_com_id = result.base_com_id or struct.unpack_from(">H", data, 0)[0]
        elif code == TCGFeatureCode.SINGLE_USER_MODE:
            result.has_single_user = True
        elif code == TCGFeatureCode.DATASTORE:
            result.has_datastore = True
        elif code == TCGFeatureCode.BLOCK_SID_AUTH:
            result.has_block_sid = True
        elif code == TCGFeatureCode.OPALITE:
            result.has_opalite = True
        elif code == TCGFeatureCode.PYRITE_V100:
            result.has_pyrite_v100 = True
        elif code == TCGFeatureCode.PYRITE_V200:
            result.has_pyrite_v200 = True
        elif code == TCGFeatureCode.RUBY_V100:
            result.has_ruby = True
        elif code == TCGFeatureCode.DATA_REMOVAL:
            result.has_data_removal = True

    @staticmethod
    def _parse_tper(result: TCGDiscovery0, data: bytes) -> None:
        if not data:
            result.tper = TCGTPerFeature()
            return
        flags = data[0]
        result.tper = TCGTPerFeature(
            sync=bool(flags & 0x01),
            async_=bool(flags & 0x02),
            ack_nack=bool(flags & 0x04),
            buffer_mgmt=bool(flags & 0x08),
            streaming=bool(flags & 0x10),
            com_id_mgmt=bool(flags & 0x40),
        )

    @staticmethod
    def _parse_locking(result: TCGDiscovery0, data: bytes) -> None:
        if not data:
            result.locking = TCGLockingFeature()
            return
        flags = data[0]
        result.locking = TCGLockingFeature(
            locking_supported=bool(flags & 0x01),
            locking_enabled=bool(flags & 0x02),
            locked=bool(flags & 0x04),
            media_encryption=bool(flags & 0x08),
            mbr_enabled=bool(flags & 0x10),
            mbr_done=bool(flags & 0x20),
        )

    @staticmethod
    def _parse_geometry(result: TCGDiscovery0, data: bytes) -> None:
        if len(data) < 28:
            result.geometry = TCGGeometryFeature()
            return
        align = bool(data[0] & 0x01)
        lbs = struct.unpack_from(">I", data, 8)[0]
        ag = struct.unpack_from(">Q", data, 12)[0]
        lal = struct.unpack_from(">Q", data, 20)[0]
        result.geometry = TCGGeometryFeature(
            align=align,
            logical_block_size=lbs,
            alignment_granularity=ag,
            lowest_aligned_lba=lal,
        )

    @staticmethod
    def _parse_opal_v200(result: TCGDiscovery0, data: bytes) -> None:
        if len(data) < 14:
            result.opal_v200 = TCGOpalV200Feature()
            return
        base_com_id, num_com_ids = struct.unpack_from(">HH", data, 0)
        range_crossing = bool(data[4] & 0x01)
        num_admin, num_user = struct.unpack_from(">HH", data, 6)
        init_pin = data[10] if len(data) > 10 else 0x00
        rev_pin = data[11] if len(data) > 11 else 0x00
        result.opal_v200 = TCGOpalV200Feature(
            base_com_id=base_com_id,
            num_com_ids=num_com_ids,
            range_crossing=range_crossing,
            num_locking_admin_auth=num_admin,
            num_locking_user_auth=num_user,
            initial_pin=init_pin,
            reverted_pin=rev_pin,
        )
        result.base_com_id = base_com_id


# =============================================================================
# ATA IF_SEND / IF_RECV command builders
# =============================================================================


def build_if_recv(security_protocol: int, com_id: int, alloc_len: int = 512) -> dict:
    """
    Build register dict for ATA TRUSTED RECEIVE (IF_RECV, 0x5C).

    The ATA TRUSTED RECEIVE command transfers security protocol data
    from the device to the host.  For TCG Opal Level 0 Discovery:
      security_protocol = 0x01
      com_id            = 0x0001

    Register layout (ACS-2, Section 7.56.3):
      Features = security_protocol
      Count    = alloc_len / 512
      LBA[7:0] = com_id[15:8]
      LBA[15:8]= com_id[7:0]

    Args:
        security_protocol: Protocol identifier (0x01 for TCG).
        com_id: ComID to address (0x0001 for Level 0 Discovery).
        alloc_len: Allocation length in bytes (must be a multiple of 512).

    Returns:
        Dict of ATA register values suitable for ATADevice.passthrough().

    Sources:
      - ACS-2 Section 7.56: TRUSTED RECEIVE.
      - TCG Storage Architecture Core Specification rev 2.01, Section 5.
    """
    sectors = max(1, alloc_len // 512)
    return {
        "features": security_protocol & 0xFF,
        "count": sectors & 0xFF,
        "lba_lo": (com_id >> 8) & 0xFF,
        "cyl_lo": com_id & 0xFF,
        "cyl_hi": 0,
        "dev": 0xA0,
        "cmd": ATA_IF_RECV,
    }


def build_if_send(security_protocol: int, com_id: int, payload: bytes) -> dict:
    """
    Build register dict for ATA TRUSTED SEND (IF_SEND, 0x5E).

    Transfers security protocol data from the host to the device.
    Used to open TCG sessions, invoke methods, and close sessions.

    Register layout (ACS-2, Section 7.57.3):
      Features = security_protocol
      Count    = len(payload) / 512
      LBA[7:0] = com_id[15:8]
      LBA[15:8]= com_id[7:0]

    Args:
        security_protocol: Protocol identifier (0x01 for TCG).
        com_id: ComID to address.
        payload: Packed ComPacket bytes to send.

    Returns:
        Dict of ATA register values suitable for ATADevice.passthrough().

    Sources:
      - ACS-2 Section 7.57: TRUSTED SEND.
      - TCG Storage Architecture Core Specification rev 2.01, Section 5.
    """
    sectors = max(1, (len(payload) + 511) // 512)
    return {
        "features": security_protocol & 0xFF,
        "count": sectors & 0xFF,
        "lba_lo": (com_id >> 8) & 0xFF,
        "cyl_lo": com_id & 0xFF,
        "cyl_hi": 0,
        "dev": 0xA0,
        "cmd": ATA_IF_SEND,
    }


# =============================================================================
# ComPacket / Packet / SubPacket builders
# =============================================================================


class TCGSession:
    """
    TCG Opal session-layer packet builder.

    TCG method invocations are wrapped in three nested layers:
      ComPacket   -- outer transport envelope tied to a ComID
      Packet      -- carries session/host sequence numbers
      SubPacket   -- carries the actual method call payload

    This class builds the packed binary structures for:
      - StartSession (method 0x0000000C on the SessionManager SP)
      - CloseSession
      - Raw method call payloads (pass-through)

    The token encoding follows TCG Core Spec rev 2.01 Section 3.2.4:
      Short atom  [0_ttt_dddd]  for integers <= 15
      Medium atom [10_tt_00_nn...nn][data]  for small byte strings
      Long atom   [111_00_0_ss_nnn...nnn][data]

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01, Section 3.2.
      - TCG Opal SSC Feature Set 2.01, Section 5.
      - sedutil: Common/DtaSession.cpp, Common/DtaCommand.cpp.
    """

    SUBPACKET_KIND_DATA = 0x0000

    @staticmethod
    def build_com_packet(extended_com_id: int, payload: bytes) -> bytes:
        """
        Wrap payload in a ComPacket envelope.

        ComPacket layout (all big-endian):
          offset  0  4 bytes reserved
          offset  4  4 bytes extendedComID
          offset  8  4 bytes outstandingData (always 0)
          offset 12  4 bytes minTransfer (always 0)
          offset 16  4 bytes length (= len(payload))

        Args:
            extended_com_id: 4-byte extended ComID (ComID in upper 2 bytes).
            payload: Packet+SubPacket bytes.

        Returns:
            Packed ComPacket bytes padded to a multiple of 512.
        """
        header = struct.pack(">IIIII", 0, extended_com_id, 0, 0, len(payload))
        raw = header + payload
        pad = (-len(raw)) % 512
        return raw + bytes(pad)

    @staticmethod
    def build_packet(tsn: int, hsn: int, seq: int, payload: bytes) -> bytes:
        """
        Wrap payload in a Packet envelope.

        Packet layout (all big-endian):
          offset  0  4 bytes TSN (target session number)
          offset  4  4 bytes HSN (host session number)
          offset  8  4 bytes seqNumber
          offset 12  2 bytes reserved
          offset 14  2 bytes ackType (0 = no ack)
          offset 16  4 bytes acknowledgement
          offset 20  4 bytes length (= len(payload))

        Args:
            tsn: Target session number (0 before session is open).
            hsn: Host session number.
            seq: Sequence number.
            payload: SubPacket bytes.
        """
        return struct.pack(">IIIHHII", tsn, hsn, seq, 0, 0, 0, len(payload)) + payload

    @staticmethod
    def build_sub_packet(payload: bytes, kind: int = 0x0000) -> bytes:
        """
        Wrap payload in a SubPacket envelope.

        SubPacket layout (all big-endian):
          offset  0  6 bytes reserved
          offset  6  2 bytes kind (0x0000 = data)
          offset  8  4 bytes length (= len(payload))

        Args:
            payload: Method call bytes.
            kind: SubPacket kind (0x0000 for normal data).
        """
        return struct.pack(">6xHI", kind, len(payload)) + payload

    @classmethod
    def build_start_session(
        cls,
        com_id: int,
        hsn: int = 0x41,
        sp_uid: bytes = b"\x00\x00\x02\x05\x00\x00\x00\x01",
        read_write: bool = True,
        host_challenge: bytes | None = None,
    ) -> bytes:
        """
        Build a StartSession method call ComPacket.

        StartSession is method UID 0x0000000C invoked on the Session
        Manager SP (UID 0x0000000000000001).  It opens a new session
        to the target Security Provider (SP) specified by sp_uid.

        After sending this packet with IF_SEND, the host reads back
        a SyncSession response with IF_RECV that provides the assigned
        TSN (Target Session Number).

        Args:
            com_id: Base ComID from Level 0 Discovery (Opal 2.0 field).
            hsn: Host-chosen session number (arbitrary, e.g. 0x41).
            sp_uid: 8-byte UID of the target SP (Admin SP = ...0x0001).
            read_write: True for R/W session (required for write methods).
            host_challenge: Optional host authentication challenge bytes.

        Returns:
            Packed ComPacket bytes ready for ATA IF_SEND.

        Sources:
          - TCG Core Spec rev 2.01, Section 5.2.2: StartSession method.
        """
        method_uid = b"\x00\x00\x00\x00\x00\x00\xFF\x02"
        session_manager_uid = b"\xFF\x00\x00\x00\x00\x00\x00\x01"

        payload = (
            b"\xF8"
            + cls._encode_bytes(session_manager_uid)
            + cls._encode_bytes(method_uid)
            + b"\xF0"
            + cls._encode_uint(hsn)
            + cls._encode_bytes(sp_uid)
            + cls._encode_uint(1 if read_write else 0)
        )

        if host_challenge is not None:
            payload += cls._encode_bytes(host_challenge)

        payload += b"\xF1\xF9"

        subpacket = cls.build_sub_packet(payload)
        packet = cls.build_packet(tsn=0, hsn=hsn, seq=1, payload=subpacket)
        extended_com_id = (com_id << 16) & 0xFFFFFFFF
        return cls.build_com_packet(extended_com_id, packet)

    @classmethod
    def build_close_session(cls, com_id: int, tsn: int, hsn: int) -> bytes:
        """
        Build a CloseSession ComPacket (empty SubPacket with ack).

        A session is closed by sending an empty data SubPacket with
        ack type 0x0001.  The TSN and HSN must match the open session.

        Args:
            com_id: Base ComID.
            tsn: Target session number returned by SyncSession.
            hsn: Host session number used in StartSession.
        """
        extended_com_id = (com_id << 16) & 0xFFFFFFFF
        subpacket = cls.build_sub_packet(b"")
        pkt = cls.build_packet(tsn=tsn, hsn=hsn, seq=2, payload=subpacket)
        return cls.build_com_packet(extended_com_id, pkt)

    @staticmethod
    def _encode_uint(value: int) -> bytes:
        """Encode a non-negative integer as a TCG short or medium atom."""
        if value < 64:
            return bytes([value & 0x3F])
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return bytes([0xC8 | len(encoded)]) + encoded

    @staticmethod
    def _encode_bytes(data: bytes) -> bytes:
        """Encode a byte string as a TCG medium atom."""
        n = len(data)
        if n <= 0x0F:
            return bytes([0xA0 | n]) + data
        return bytes([0xD0 | (n >> 8), n & 0xFF]) + data


# =============================================================================
# High-level client
# =============================================================================


class TCGOpalClient:
    """
    High-level TCG Opal client for self-encrypting drive interaction.

    This client handles the full workflow for interacting with an Opal-
    compliant SED:
      1. Issue Level 0 Discovery (IF_RECV) to detect SSC features.
      2. Extract the BaseComID and feature flags.
      3. Build StartSession packets for subsequent method invocations.

    The client does NOT implement the full Opal method call table; it
    provides the transport layer and Discovery 0 parsing needed for:
      - Enumerating drive security features
      - Scripting StartSession for external tools (sedutil, pyrite-sed)
      - Testing for frozen/locked state before attempting bypass

    Sources:
      - TCG Storage Architecture Core Specification rev 2.01.
      - TCG Opal SSC Feature Set 2.01.
      - Boteanu & Bhargava, "Bypassing Self-Encrypting Drives" (BHEU 2015).
      - sedutil v1.15 source (open source reference implementation).
    """

    SECURITY_PROTOCOL_TCG = TRUSTED_SECURITY_PROTOCOL_TCG
    LEVEL0_COMID = TCG_LEVEL0_COMID
    ALLOC_LEN = 512

    def __init__(self, device: ATADevice):
        self.dev = device

    def level0_discovery(self) -> TCGDiscovery0:
        """
        Perform ATA IF_RECV Level 0 Discovery and parse the response.

        Sends ATA TRUSTED RECEIVE (0x5C) with protocol 0x01, ComID 0x0001
        and reads back 512 bytes of feature descriptor data.

        Returns:
            Parsed TCGDiscovery0 with all feature flags populated.
        """
        regs = build_if_recv(
            security_protocol=self.SECURITY_PROTOCOL_TCG,
            com_id=self.LEVEL0_COMID,
            alloc_len=self.ALLOC_LEN,
        )
        data = self.dev.passthrough(regs, data_in_size=self.ALLOC_LEN)
        return TCGDiscovery0Parser.parse(data)

    def start_session_packet(
        self,
        discovery: TCGDiscovery0,
        hsn: int = 0x41,
        sp_uid: bytes = b"\x00\x00\x02\x05\x00\x00\x00\x01",
        read_write: bool = True,
        host_challenge: bytes | None = None,
    ) -> bytes:
        """
        Build a StartSession ComPacket using the BaseComID from discovery.

        Args:
            discovery: Result of level0_discovery().
            hsn: Host-chosen session number (arbitrary).
            sp_uid: 8-byte SP UID (default: Admin SP).
            read_write: True for read/write session.
            host_challenge: Optional host challenge bytes.

        Returns:
            Packed ComPacket bytes for ATA IF_SEND.
        """
        return TCGSession.build_start_session(
            com_id=discovery.base_com_id,
            hsn=hsn,
            sp_uid=sp_uid,
            read_write=read_write,
            host_challenge=host_challenge,
        )

    def send_packet(self, com_id: int, payload: bytes) -> bytes:
        """
        Send a ComPacket via ATA IF_SEND and read back the response.

        Args:
            com_id: Base ComID from Discovery 0.
            payload: Packed ComPacket bytes.

        Returns:
            Raw 512-byte IF_RECV response.
        """
        send_regs = build_if_send(
            security_protocol=self.SECURITY_PROTOCOL_TCG,
            com_id=com_id,
            payload=payload,
        )
        self.dev.passthrough(send_regs, data_out=payload)
        recv_regs = build_if_recv(
            security_protocol=self.SECURITY_PROTOCOL_TCG,
            com_id=com_id,
            alloc_len=self.ALLOC_LEN,
        )
        return self.dev.passthrough(recv_regs, data_in_size=self.ALLOC_LEN)
