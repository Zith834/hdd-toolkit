from hdd_firmware_toolkit.exploit.hotpatch import PatchTemplates
from hdd_firmware_toolkit.firmware.patcher import FirmwarePatch, FirmwarePatcher


def test_patcher_detect_vendor():
    patcher = FirmwarePatcher(bytes(512), vendor="unknown")
    assert patcher.vendor == "unknown"


def test_patcher_detect_vendor_explicit():
    patcher = FirmwarePatcher(bytes(512), vendor="wd")
    assert patcher.vendor == "wd"


def test_patcher_apply_patch():
    data = bytearray(512)
    data[0:4] = b"\x00\x00\x00\x00"
    patch = FirmwarePatch(offset=0, original=b"\x00" * 4,
                          replacement=b"\xFF" * 4, description="test")
    patcher = FirmwarePatcher(bytes(data), vendor="unknown")
    patcher.apply_patch(patch)
    assert patcher.data[0:4] == b"\xFF" * 4


def test_patcher_rollback():
    data = bytearray(512)
    data[0:4] = b"\x00\x00\x00\x00"
    patch = FirmwarePatch(offset=0, original=b"\x00" * 4,
                          replacement=b"\xFF" * 4, description="test")
    patcher = FirmwarePatcher(bytes(data), vendor="unknown")
    patcher.apply_patch(patch)
    patcher.rollback(patch)
    assert patcher.data[0:4] == b"\x00" * 4


def test_patcher_fix_all():
    data = bytearray(512)
    patcher = FirmwarePatcher(bytes(data), vendor="unknown")
    fixes = patcher.fix_all()
    assert isinstance(fixes, list)


def test_patcher_write(tmp_path):
    data = bytearray(512)
    patcher = FirmwarePatcher(bytes(data), vendor="unknown")
    output = tmp_path / "patched.bin"
    patcher.write(str(output))
    assert output.exists()
    assert len(output.read_bytes()) == 512


def test_patch_templates_nop_sled():
    sled = PatchTemplates.build_nop_sled(size=16)
    assert len(sled) == 16


def test_patch_templates_exfil_hook():
    hook = PatchTemplates.exfiltration_hook(
        buffer_addr=0x20000000,
        host_signal_addr=0x40000000,
    )
    assert hook != b""


def test_patch_templates_smart_redirect():
    redirect = PatchTemplates.smart_log_redirect(target_log=0xBE)
    assert len(redirect) > 0
