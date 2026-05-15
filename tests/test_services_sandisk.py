import struct

from hdd_firmware_toolkit.nvme.admin import NVMeAdminCmd, NVMeAdminPassthrough
from hdd_firmware_toolkit.nvme.sandisk import SanDiskNVMeVSC


class TestSanDiskNVMeVSC:

    def test_constants(self):
        assert SanDiskNVMeVSC.VID_SANDISK == 0x15b7
        assert SanDiskNVMeVSC.VID_WDC == 0x1c58
        assert SanDiskNVMeVSC.VID_WDC_2 == 0x1b96
        assert SanDiskNVMeVSC.LOG_C0_EOL_STATUS == 0xC0
        assert SanDiskNVMeVSC.VU_CAP_DIAG_CMD == 0xC6
        assert SanDiskNVMeVSC.VU_PURGE == 0xDD
        assert SanDiskNVMeVSC.FID_LATENCY_MONITOR == 0xC5

    def test_sn740_device_ids(self):
        assert 0x5015 in SanDiskNVMeVSC.DID_SN740
        assert 0x5016 in SanDiskNVMeVSC.DID_SN740
        assert 0x5017 in SanDiskNVMeVSC.DID_SN740
        assert 0x5025 in SanDiskNVMeVSC.DID_SN740

    def test_sn560_device_ids(self):
        assert 0x2712 in SanDiskNVMeVSC.DID_SN560
        assert 0x2713 in SanDiskNVMeVSC.DID_SN560
        assert 0x2714 in SanDiskNVMeVSC.DID_SN560

    def test_uuids(self):
        assert len(SanDiskNVMeVSC.WDC_UUID) == 16
        assert len(SanDiskNVMeVSC.SNDK_UUID) == 16
        assert SanDiskNVMeVSC.WDC_UUID[0] == 0x2d
        assert SanDiskNVMeVSC.SNDK_UUID[0] == 0xde

    def test_build_get_log_page(self):
        cmd = SanDiskNVMeVSC.build_get_log_page(0xC0, 512)
        assert isinstance(cmd, NVMeAdminCmd)
        assert cmd.opcode == NVMeAdminPassthrough.GET_LOG_PAGE
        assert cmd.data_len == 512

    def test_build_get_log_page_c1(self):
        cmd = SanDiskNVMeVSC.build_get_log_page(0xC1, 0x4000)
        assert cmd.data_len == 0x4000

    def test_build_get_log_page_with_uuid(self):
        cmd = SanDiskNVMeVSC.build_get_log_page(0xC2, 512, uuid_index=1)
        assert (cmd.cdw10 >> 12) & 0x0F == 1

    def test_build_vu_admin_cmd(self):
        cmd = SanDiskNVMeVSC.build_vu_admin_cmd(0xDD, cdw10=0x0000000C)
        assert cmd.opcode == 0xDD
        assert cmd.cdw10 == 0x0000000C

    def test_build_vu_admin_cmd_with_data(self):
        cmd = SanDiskNVMeVSC.build_vu_admin_cmd(
            0xC6, cdw10=0x2305, data_len=4096, data=b'test')
        assert cmd.data == b'test'
        assert cmd.data_len == 4

    def test_build_cap_diag(self):
        cmd = SanDiskNVMeVSC.build_vu_cap_diag(subcmd=0x00)
        assert cmd.opcode == 0xC6
        assert cmd.cdw10 == 0x00

    def test_build_purge_cmd(self):
        cmd = SanDiskNVMeVSC.build_purge_cmd()
        assert cmd.opcode == 0xDD
        assert cmd.cdw10 == 0x0000000C
        assert cmd.timeout_ms == 30000

    def test_build_purge_monitor_cmd(self):
        cmd = SanDiskNVMeVSC.build_purge_monitor_cmd()
        assert cmd.opcode == 0xDE
        assert cmd.data_len == 0x2F

    def test_build_drive_resize_cmd(self):
        cmd = SanDiskNVMeVSC.build_drive_resize_cmd(0x100000)
        assert cmd.opcode == 0xCC
        assert cmd.cdw10 == 0x0301
        assert cmd.cdw11 == 0x100000
        assert cmd.cdw12 == 0

    def test_build_clear_assert_dump_cmd(self):
        cmd = SanDiskNVMeVSC.build_clear_assert_dump_cmd()
        assert cmd.opcode == 0xD8
        assert cmd.cdw10 == 0x0305

    def test_build_clear_pcie_errors_vuc(self):
        cmd = SanDiskNVMeVSC.build_clear_pcie_errors_vuc_cmd()
        assert cmd.opcode == 0xD2
        assert cmd.cdw10 == 0x0104

    def test_build_clear_fw_act_history_cmd(self):
        cmd = SanDiskNVMeVSC.build_clear_fw_act_history_cmd()
        assert cmd.opcode == 0xC6
        assert cmd.cdw10 == 0x2305

    def test_build_c0_eol_log(self):
        cmd = SanDiskNVMeVSC.build_get_c0_eol_log()
        assert cmd.data_len == 0x200

    def test_build_c1_add_smart_log(self):
        cmd = SanDiskNVMeVSC.build_get_c1_add_smart_log()
        assert cmd.data_len == 0x4000

    def test_build_c2_dev_mgmt_log(self):
        cmd = SanDiskNVMeVSC.build_get_c2_dev_mgmt_log()
        assert cmd.data_len == 0x1000

    def test_build_d0_vu_smart_log(self):
        cmd = SanDiskNVMeVSC.build_get_d0_vu_smart_log()
        assert cmd.data_len == 0x200

    def test_build_ca_device_info_log(self):
        cmd = SanDiskNVMeVSC.build_get_ca_device_info_log()
        assert cmd.data_len == 0xA0

    def test_build_cb_fw_act_history_log(self):
        cmd = SanDiskNVMeVSC.build_get_cb_fw_act_history_log()
        assert cmd.data_len == 0x3D0

    def test_parse_c0_eol_log(self):
        data = bytearray(512)
        struct.pack_into('<I', data, 76, 1234)
        struct.pack_into('<I', data, 88, 95)
        parsed = SanDiskNVMeVSC.parse_c0_eol_log(data)
        assert parsed['realloc_block_count'] == 1234
        assert parsed['percent_life_remaining'] == 95

    def test_parse_c0_eol_log_short(self):
        parsed = SanDiskNVMeVSC.parse_c0_eol_log(b'\x00' * 64)
        assert 'error' in parsed

    def test_parse_ca_device_info_log(self):
        data = bytearray(256)
        struct.pack_into('<Q', data, 0x00, 0xABCD)
        struct.pack_into('<B', data, 0x77, 42)
        parsed = SanDiskNVMeVSC.parse_ca_device_info_log(data)
        assert parsed['nand_bytes_written_lo'] == 0xABCD
        assert parsed['percent_free_blocks'] == 42

    def test_parse_ca_device_info_log_short(self):
        parsed = SanDiskNVMeVSC.parse_ca_device_info_log(b'\x00' * 64)
        assert 'error' in parsed

    def test_parse_d0_vu_smart_log(self):
        data = bytearray(512)
        struct.pack_into('<I', data, 0x08, 0x1234)
        struct.pack_into('<I', data, 0x34, 45)
        parsed = SanDiskNVMeVSC.parse_d0_vu_smart_log(data)
        assert parsed['lifetime_power_on_hours'] == 0x1234
        assert parsed['current_temperature'] == 45

    def test_parse_d0_vu_smart_log_short(self):
        parsed = SanDiskNVMeVSC.parse_d0_vu_smart_log(b'\x00' * 128)
        assert 'error' in parsed

    def test_is_sandisk_nvme(self):
        data = bytearray(4096)
        struct.pack_into('<H', data, 0, 0x15b7)
        assert SanDiskNVMeVSC.is_sandisk_nvme(data)

    def test_is_not_sandisk_nvme(self):
        data = bytearray(4096)
        struct.pack_into('<H', data, 0, 0x8086)
        assert not SanDiskNVMeVSC.is_sandisk_nvme(data)

    def test_get_model_family_sn740(self):
        assert SanDiskNVMeVSC.get_model_family(0x15b7, 0x5015) == 'SN740'
        assert SanDiskNVMeVSC.get_model_family(0x15b7, 0x5016) == 'SN740'
        assert SanDiskNVMeVSC.get_model_family(0x15b7, 0x5025) == 'SN740'

    def test_get_model_family_sn560(self):
        assert SanDiskNVMeVSC.get_model_family(0x15b7, 0x2712) == 'SN560'

    def test_get_model_family_unknown(self):
        assert SanDiskNVMeVSC.get_model_family(0x15b7, 0x9999) == 'Not SanDisk/WD'

    def test_get_model_family_wdc_unknown(self):
        result = SanDiskNVMeVSC.get_model_family(0x1c58, 0x9999)
        assert result == 'WD DC (unknown)'

    def test_get_model_family_non_wdc(self):
        result = SanDiskNVMeVSC.get_model_family(0x8086, 0x0000)
        assert result == 'Not SanDisk/WD'

    def test_sniff_vendor_log_pages(self):
        data = bytearray(4096)
        struct.pack_into('<H', data, 0, 0x15b7)
        struct.pack_into('<H', data, 2, 0x5015)
        result = SanDiskNVMeVSC.sniff_vendor_log_pages(data)
        assert result['vid'] == '0x15B7'
        assert result['family'] == 'SN740'
        assert result['vendor'] == 'SanDisk'
        assert len(result['log_pages']) >= 6
        log_ids = [p['log_id'] for p in result['log_pages']]
        assert 0xC0 in log_ids
        assert 0xCA in log_ids
        assert 0xD0 in log_ids

    def test_sniff_vendor_log_pages_non_sandisk(self):
        data = bytearray(4096)
        struct.pack_into('<H', data, 0, 0x8086)
        result = SanDiskNVMeVSC.sniff_vendor_log_pages(data)
        assert result == []

    def test_parse_c2_dev_mgmt_log(self):
        data = bytearray(512)
        off = 16
        for eid, val in [(0x1E, 3), (0x18, 1)]:
            struct.pack_into('<I', data, off, 12)
            struct.pack_into('<I', data, off + 4, eid)
            struct.pack_into('<I', data, off + 8, val)
            off += 12
        parsed = SanDiskNVMeVSC.parse_c2_dev_mgmt_log(data)
        assert 'format_corrupt_reason' in parsed
        assert 'thermal_throttle' in parsed

    def test_parse_c2_dev_mgmt_log_short(self):
        parsed = SanDiskNVMeVSC.parse_c2_dev_mgmt_log(b'\x00' * 8)
        assert 'error' in parsed
