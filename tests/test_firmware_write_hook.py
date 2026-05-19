from hdd_toolkit.firmware.write_hook import (
    ArmSoftwareBreakpoint,
    FirmwareOverlayLoader,
    WriteHookPoint,
)


def test_write_hook_point_valid():
    hook = WriteHookPoint(
        cache_evict_fn_addr=0x1000,
        hook_trampoline_addr=0x2000,
        hook_payload_addr=0x3000,
        intercept_mode="pre_commit",
    )
    assert hook.is_valid() is True


def test_write_hook_point_invalid_unaligned():
    hook = WriteHookPoint(
        cache_evict_fn_addr=0x1001,
        hook_trampoline_addr=0x2000,
        hook_payload_addr=0x3000,
        intercept_mode="pre_commit",
    )
    assert hook.is_valid() is False


def test_trampoline_bytes_length():
    hook = WriteHookPoint(
        cache_evict_fn_addr=0x1000,
        hook_trampoline_addr=0x2000,
        hook_payload_addr=0x3000,
        intercept_mode="post_cache",
    )
    assert len(hook.trampoline_bytes()) == 12


def test_undef_instruction_encoding():
    bp = ArmSoftwareBreakpoint(target_addr=0x1000, original_instruction=0)
    assert bp.encode_undef_instruction() == b"\xf0\x01\xf0\xe7"


def test_thumb_bkpt_encoding():
    bp = ArmSoftwareBreakpoint(target_addr=0x1000, original_instruction=0)
    assert bp.encode_thumb_bkpt() == b"\xbe\xbe"


def test_is_thumb_addr():
    assert ArmSoftwareBreakpoint.is_thumb_addr(0x1001) is True
    assert ArmSoftwareBreakpoint.is_thumb_addr(0x1000) is False


def test_overlay_loader_hook_bytes_length():
    loader = FirmwareOverlayLoader({4: 0x8000})
    assert len(loader.hook_overlay_loader(0x1000, 0x2000)) == 4


def test_diagnostic_overlay_ids():
    assert FirmwareOverlayLoader.DIAGNOSTIC_OVERLAY_IDS == [4, 5]


def test_get_overlay_load_addr_missing():
    loader = FirmwareOverlayLoader({4: 0x8000})
    assert loader.get_overlay_load_addr(99) is None
