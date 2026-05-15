import ctypes
import os
import struct
from dataclasses import dataclass


@dataclass
class NVMeAdminCmd:
    """Describes a complete NVMe admin command for passthrough submission."""

    opcode: int
    nsid: int
    cdw10: int = 0
    cdw11: int = 0
    cdw12: int = 0
    cdw13: int = 0
    cdw14: int = 0
    cdw15: int = 0
    data_len: int = 0
    data: bytes = b""
    timeout_ms: int = 5000
    is_write: bool = False


class NvmePassthruCmd(ctypes.Structure):
    """
    Linux nvme_passthru_cmd struct for NVME_IOCTL_ADMIN_CMD.

    Matches the 72-byte layout from linux/nvme_ioctl.h (without the
    kernel-5.19+ status field).  The ioctl number 0xC0484E41 encodes
    this 72-byte size on x86-64.

    Sources:
      - include/uapi/linux/nvme_ioctl.h (struct nvme_passthru_cmd)
    """

    _fields_ = [
        ("opcode", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("rsvd1", ctypes.c_uint16),
        ("nsid", ctypes.c_uint32),
        ("cdw2", ctypes.c_uint32),
        ("cdw3", ctypes.c_uint32),
        ("metadata", ctypes.c_uint64),
        ("addr", ctypes.c_uint64),
        ("metadata_len", ctypes.c_uint32),
        ("data_len", ctypes.c_uint32),
        ("cdw10", ctypes.c_uint32),
        ("cdw11", ctypes.c_uint32),
        ("cdw12", ctypes.c_uint32),
        ("cdw13", ctypes.c_uint32),
        ("cdw14", ctypes.c_uint32),
        ("cdw15", ctypes.c_uint32),
        ("timeout_ms", ctypes.c_uint32),
        ("result", ctypes.c_uint32),
    ]


def _hex_dump(data: bytes, width: int = 16) -> str:
    """Format a hex dump similar to xxd."""
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


class NVMeDevice:
    """
    Live NVMe device handle for executing admin commands via ioctl.

    Opens /dev/nvme{number} and provides send() for NVMeAdminCmd objects.

    Usage:
        with NVMeDevice(0) as dev:
            cmd = NVMeAdminPassthrough.identify_ctrlr()
            data = dev.send(cmd)
            print(data[:64].hex())

    Sources:
      - include/uapi/linux/nvme_ioctl.h (NVME_IOCTL_ADMIN_CMD = _IOWR('N', 0x41, 72))
    """

    def __init__(self, device: int | str):
        self._path = f"/dev/nvme{device}" if isinstance(device, int) else device
        self._fd: int | None = None

    def __enter__(self):
        self._fd = os.open(self._path, os.O_RDWR)
        return self

    def __exit__(self, *exc):
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    @property
    def fileno(self) -> int:
        if self._fd is None:
            raise RuntimeError(f"Device {self._path} not opened")
        return self._fd

    def send(self, cmd: NVMeAdminCmd) -> bytes:
        """
        Execute an NVMe admin command and return the response data.

        For read commands (data_len > 0, is_write=False), allocates a buffer
        of data_len bytes and returns its contents after the ioctl.

        For write commands (is_write=True), sends cmd.data to the device.
        Returns completion result as a 4-byte int (struct.result).

        Raises OSError if the ioctl fails.
        """
        pcmd = NvmePassthruCmd()
        pcmd.opcode = cmd.opcode & 0xFF
        pcmd.flags = 0
        pcmd.nsid = cmd.nsid & 0xFFFFFFFF
        pcmd.cdw2 = 0
        pcmd.cdw3 = 0
        pcmd.metadata = 0
        pcmd.metadata_len = 0
        pcmd.cdw10 = cmd.cdw10
        pcmd.cdw11 = cmd.cdw11
        pcmd.cdw12 = cmd.cdw12
        pcmd.cdw13 = cmd.cdw13
        pcmd.cdw14 = cmd.cdw14
        pcmd.cdw15 = cmd.cdw15
        pcmd.timeout_ms = cmd.timeout_ms
        pcmd.result = 0

        data_len = cmd.data_len
        if cmd.is_write and cmd.data:
            buf = ctypes.create_string_buffer(cmd.data)
            pcmd.addr = ctypes.addressof(buf)
            pcmd.data_len = len(cmd.data)
        elif data_len > 0:
            buf = ctypes.create_string_buffer(data_len)
            pcmd.addr = ctypes.addressof(buf)
            pcmd.data_len = data_len
        else:
            buf = None
            pcmd.addr = 0
            pcmd.data_len = 0

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ret = libc.ioctl(self.fileno, 0xC0484E41, ctypes.byref(pcmd))
        if ret < 0:
            errno = ctypes.get_errno()
            raise OSError(errno, os.strerror(errno))

        if buf is not None and data_len > 0 and not cmd.is_write:
            return buf.raw[:data_len]
        return struct.pack("<I", pcmd.result)


class NVMeAdminPassthrough:
    """
    Build and format NVMe admin commands for submission via
    Linux /dev/ng0n1 or /dev/nvme0 (NVMe passthrough ioctl).

    The Linux kernel exposes NVMe admin passthrough via:
      - NVMe_IOCTL_ADMIN_CMD (on /dev/nvme0, /dev/ng0n1)
      - /sys/class/nvme/nvme0/device/subsystem

    Command submission flow:
      1. Allocate a 4KB-aligned DMA buffer
      2. Fill the nvme_passthru_cmd struct:
            opcode, nsid, cdw10-15, data_len, data_ptr, timeout_ms
            result (completion result), status (completion status)
      3. ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd)
      4. Read completion data from buffer

    NVMe admin commands are 64 bytes: 4 DW opcode + 16 DW CDW + payload.

    Useful admin commands for firmware hacking:
      - 0x01: IDENTIFY (namespace, controller)
      - 0x06: GET LOG PAGE (SMART, error, firmware, etc.)
      - 0x09: GET FEATURES
      - 0x0A: SET FEATURES
      - 0x10: FIRMWARE DOWNLOAD
      - 0x11: FIRMWARE ACTIVATE
      - 0x14: DEVICE SELF TEST
      - 0x80-0xFF: VENDOR SPECIFIC (OEM debug, firmware flash, SA read/write)
    """

    # NVMe admin opcodes
    DELETE_IO_SQ = 0x00
    CREATE_IO_SQ = 0x01
    GET_LOG_PAGE = 0x02
    DELETE_IO_CQ = 0x04
    CREATE_IO_CQ = 0x05
    IDENTIFY = 0x06
    ABORT = 0x08
    SET_FEATURES = 0x09
    GET_FEATURES = 0x0A
    ASYNCHRONOUS_EVENT_REQUEST = 0x0C
    NAMESPACE_MANAGEMENT = 0x0D
    FIRMWARE_DOWNLOAD = 0x11
    FIRMWARE_ACTIVATE = 0x10
    DEVICE_SELF_TEST = 0x14
    NAMESPACE_ATTACHMENT = 0x15
    KEEP_ALIVE = 0x18
    DIRECTIVE_SEND = 0x19
    DIRECTIVE_RECEIVE = 0x1A
    VIRTUALIZATION_MANAGEMENT = 0x1C
    DOORBELL_BUFFER_CONFIG = 0x7C
    FORMAT_NVM = 0x80
    SECURITY_SEND = 0x81
    SECURITY_RECEIVE = 0x82
    SANITIZE = 0x84

    # Get Log Page identifiers
    LOG_SUPPORTED_LOG_PAGES = 0x00
    LOG_ERROR_INFO = 0x01
    LOG_SMART = 0x02
    LOG_FIRMWARE_SLOT = 0x03
    LOG_CHANGED_NS_LIST = 0x04
    LOG_COMMANDS_EFFECTS = 0x05
    LOG_DEVICE_SELF_TEST = 0x06
    LOG_TELEMETRY_HOST = 0x07
    LOG_TELEMETRY_CTLR = 0x08
    LOG_ENDURANCE_GROUP = 0x09
    LOG_PREDICTABLE_LATENCY = 0x0A
    LOG_PERSISTENT_EVENT = 0x0D
    LOG_LBA_STATUS = 0x10
    LOG_ENDURANCE_GROUP_EVT = 0x11

    # Identify CNS values
    CNS_ID_CTRLR = 0x01  # controller
    CNS_ID_ACT_NS = 0x02  # active namespace list
    CNS_ID_NS = 0x00  # namespace
    CNS_NS_DESCR = 0x03  # namespace descriptor

    # Linux NVMe ioctl
    NVME_IOCTL_ADMIN_CMD = 0xC0484E41

    @staticmethod
    def build_passthru_cmd(cmd: NVMeAdminCmd) -> dict:
        """
        Build an nvme_passthru_cmd struct as a dict suitable for passing
        to struct.pack / ctypes or directly formatting for an ioctl.

        nvme_passthru_cmd layout (from linux/nvme_ioctl.h):
          [0]   opcode (u8)
          [1]   flags (u8)
          [2]   reserved (u16)
          [4]   nsid (u32)
          [8]   cdw2 (u32)
          [12]  cdw3 (u32)
          [16]  metadata (u64)
          [24]  addr (u64)       -- DMA buffer pointer
          [32]  metadata_len (u32)
          [36]  data_len (u32)
          [40]  cdw10 (u32)
          [44]  cdw11 (u32)
          [48]  cdw12 (u32)
          [52]  cdw13 (u32)
          [56]  cdw14 (u32)
          [60]  cdw15 (u32)
          [64]  timeout_ms (u32)
          [68]  result (u32)
          [72]  status (u32)
          total: 76 bytes
        """
        return {
            "opcode": cmd.opcode & 0xFF,
            "flags": 0,
            "nsid": cmd.nsid & 0xFFFFFFFF,
            "cdw2": 0,
            "cdw3": 0,
            "metadata": 0,
            "addr": 0,  # must be filled by the caller with DMA-safe buffer
            "metadata_len": 0,
            "data_len": cmd.data_len,
            "cdw10": cmd.cdw10,
            "cdw11": cmd.cdw11,
            "cdw12": cmd.cdw12,
            "cdw13": cmd.cdw13,
            "cdw14": cmd.cdw14,
            "cdw15": cmd.cdw15,
            "timeout_ms": cmd.timeout_ms,
            "result": 0,
            "status": 0,
        }

    @staticmethod
    def identify_ctrlr() -> NVMeAdminCmd:
        """Build IDENTIFY controller command -- returns 4096-byte controller data."""
        return NVMeAdminCmd(
            opcode=NVMeAdminPassthrough.IDENTIFY,
            nsid=0,
            cdw10=NVMeAdminPassthrough.CNS_ID_CTRLR,
            data_len=4096,
        )

    @staticmethod
    def identify_ns(nsid: int = 1) -> NVMeAdminCmd:
        """Build IDENTIFY namespace command -- returns 4096-byte namespace data."""
        return NVMeAdminCmd(
            opcode=NVMeAdminPassthrough.IDENTIFY,
            nsid=nsid,
            cdw10=NVMeAdminPassthrough.CNS_ID_NS,
            data_len=4096,
        )

    @staticmethod
    def get_log_page(
        log_id: int, nsid: int = 0xFFFFFFFF, offset: int = 0, size: int = 512
    ) -> NVMeAdminCmd:
        """Build GET LOG PAGE command for the given log identifier."""
        # cdw10 = (log_id << 0) | (nsid_selector << 8) | (numdl << 16)
        numdl = (size // 4) - 1  # number of dwords - 1 (lower 16 bits)
        cdw10 = (log_id & 0xFF) | (numdl << 16)
        cdw11 = offset & 0xFFFFFFFF
        cdw12 = (offset >> 32) & 0xFFFFFFFF
        cdw13 = size >> 16  # numdu (upper dwords)
        return NVMeAdminCmd(
            opcode=NVMeAdminPassthrough.GET_LOG_PAGE,
            nsid=nsid,
            cdw10=cdw10,
            cdw11=cdw11,
            cdw12=cdw12,
            cdw13=cdw13,
            data_len=size,
        )

    @staticmethod
    def get_smart_log(nsid: int = 0xFFFFFFFF) -> NVMeAdminCmd:
        """Build GET LOG PAGE for SMART / Health Information (log 0x02, 512 bytes)."""
        return NVMeAdminPassthrough.get_log_page(
            log_id=NVMeAdminPassthrough.LOG_SMART, nsid=nsid, size=512
        )

    @staticmethod
    def get_firmware_slot_log() -> NVMeAdminCmd:
        """Build GET LOG PAGE for Firmware Slot Information (log 0x03, 512 bytes)."""
        return NVMeAdminPassthrough.get_log_page(
            log_id=NVMeAdminPassthrough.LOG_FIRMWARE_SLOT, nsid=0xFFFFFFFF, size=512
        )

    @staticmethod
    def firmware_download(offset: int, data: bytes) -> NVMeAdminCmd:
        """
        Build FIRMWARE DOWNLOAD command.
        offset: offset in firmware download buffer (dwords)
        data: firmware data to download (must be 4-byte aligned)
        """
        if len(data) % 4 != 0:
            data += b"\x00" * (4 - len(data) % 4)
        numd = (len(data) // 4) - 1  # number of dwords - 1
        return NVMeAdminCmd(
            opcode=NVMeAdminPassthrough.FIRMWARE_DOWNLOAD,
            nsid=0,
            cdw10=numd & 0xFFFF,
            cdw11=offset,
            data_len=len(data),
            data=data,
            is_write=True,
        )

    @staticmethod
    def firmware_activate(slot: int = 1, action: int = 0x01) -> NVMeAdminCmd:
        """
        Build FIRMWARE ACTIVATE command.
        action: 0x01=replace, 0x02=replace+enable, 0x03=replace+enable+reset
        slot: firmware slot to activate (1-7)
        """
        return NVMeAdminCmd(
            opcode=NVMeAdminPassthrough.FIRMWARE_ACTIVATE,
            nsid=0xFFFFFFFF,
            cdw10=(action & 0x0F) | ((slot & 0x07) << 16),
            data_len=0,
        )

    @staticmethod
    def sanitize(action: int = 0x01, ovrpat: int = 0) -> NVMeAdminCmd:
        """
        Build SANITIZE command.
        action: 0x00=exit failure mode, 0x01=block erase, 0x02=overwrite,
                0x03=block erase + crypto erase
        ovrpat: overwrite pattern (only used for overwrite sanitize)
        """
        # cdw10: bit 0-2 = action, bit 3=no deallocate, bit 9-15=overwrite pattern
        cdw10 = (action & 0x07) | (ovrpat << 8)
        return NVMeAdminCmd(
            opcode=NVMeAdminPassthrough.SANITIZE,
            nsid=0xFFFFFFFF,
            cdw10=cdw10,
            data_len=0,
        )

    @staticmethod
    def vendor_specific(
        opcode: int,
        cdw10: int = 0,
        cdw11: int = 0,
        cdw12: int = 0,
        cdw13: int = 0,
        data_len: int = 0,
        data: bytes = b"",
        nsid: int = 0,
        is_write: bool = False,
    ) -> NVMeAdminCmd:
        """
        Build a vendor-specific NVMe admin command (opcode 0x80-0xFF).
        Used for OEM debug, service area access, manufacturing commands.
        Examples: Samsung vendor debug (0xC0, 0xC1), WD/HGST SA read (0xD0+).
        """
        return NVMeAdminCmd(
            opcode=opcode,
            nsid=nsid,
            cdw10=cdw10,
            cdw11=cdw11,
            cdw12=cdw12,
            cdw13=cdw13,
            data_len=data_len,
            data=data,
            is_write=is_write,
        )

    @staticmethod
    def parse_identify_ctrlr(data: bytes) -> dict:
        """Parse key fields from IDENTIFY CONTROLLER 4096-byte buffer."""
        if len(data) < 4096:
            return {}

        def _s(offset, length):
            return (
                data[offset : offset + length]
                .split(b"\x00", 1)[0]
                .decode("ascii", errors="replace")
            )

        return {
            "vendor_id": struct.unpack_from("<H", data, 0)[0],
            "subsystem_vendor": struct.unpack_from("<H", data, 2)[0],
            "serial_number": _s(4, 20),
            "model_number": _s(24, 40),
            "firmware_rev": _s(64, 8),
            "max_data_xfer": struct.unpack_from("<I", data, 77)[0],
            "oacs": struct.unpack_from("<H", data, 256)[0],
            "lpa": data[260],
            "sqes": data[512],
            "cqes": data[513],
            "nn": struct.unpack_from("<I", data, 516)[0],  # number of namespaces
            "acl": data[260],
        }

    @staticmethod
    def parse_smart_log(data: bytes) -> dict:
        """Parse 512-byte SMART / Health Information log."""
        if len(data) < 512:
            return {}
        return {
            "critical_warning": data[0],
            "temperature": struct.unpack_from("<H", data, 1)[0],
            "available_spare": data[3],
            "available_spare_thresh": data[4],
            "percentage_used": data[5],
            "data_units_read": struct.unpack_from("<Q", data, 32)[0],
            "data_units_written": struct.unpack_from("<Q", data, 40)[0],
            "host_reads": struct.unpack_from("<Q", data, 48)[0],
            "host_writes": struct.unpack_from("<Q", data, 56)[0],
            "ctrl_busy_time": struct.unpack_from("<Q", data, 64)[0],
            "power_cycles": struct.unpack_from("<Q", data, 72)[0],
            "power_on_hours": struct.unpack_from("<Q", data, 80)[0],
            "unsafe_shutdowns": struct.unpack_from("<Q", data, 88)[0],
            "media_errors": struct.unpack_from("<Q", data, 96)[0],
            "num_err_log_entries": struct.unpack_from("<Q", data, 104)[0],
        }

    @staticmethod
    def parse_firmware_slot_log(data: bytes) -> dict:
        """Parse 512-byte Firmware Slot Information log (log 0x03)."""
        if len(data) < 512:
            return {}
        active_slot = data[0] & 0x07
        slots = []
        for i in range(7):
            off = 32 + i * 8
            rev = data[off : off + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
            slots.append({"slot": i + 1, "revision": rev or "(empty)"})
        return {
            "afi": active_slot,
            "active_slot": active_slot,
            "next_reset_slot": (data[0] >> 4) & 0x07,
            "slots": slots,
        }

    @staticmethod
    def execute_admin_cmd(device: int | str, cmd: NVMeAdminCmd) -> bytes:
        """
        Execute an NVMe admin command on a live device and return response data.

        This is a convenience wrapper around NVMeDevice that opens the device,
        sends one command, and returns the raw response bytes.  For write
        commands, the return value is the completion result packed as 4 bytes.

        Args:
            device: NVMe device number (e.g. 0 for /dev/nvme0) or device path.
            cmd: The NVMeAdminCmd to execute.

        Returns:
            Raw response data (for read commands) or completion result bytes.

        Raises:
            OSError: If the device cannot be opened or the ioctl fails.
        """
        with NVMeDevice(device) as dev:
            return dev.send(cmd)
