from hdd_toolkit.nvme.envme import eNVMeIntegration
from hdd_toolkit.nvme.ofabrics import NVMeOverFabrics
from hdd_toolkit.nvme.timing import NVMeTimingSideChannel


def test_build_read_cmd():
    cmd = NVMeTimingSideChannel.build_read_cmd(nsid=1, slba=0, nlb=1)
    assert cmd.opcode == 0x02


def test_estimate_read_latency():
    times = [100, 110, 95, 105, 2000, 98]
    result = NVMeTimingSideChannel.estimate_read_latency(times)
    assert "mean_us" in result


def test_detect_content_contention():
    baseline = {"mean_us": 100, "std_us": 10}
    sample = {"mean_us": 300, "std_us": 50}
    result = NVMeTimingSideChannel.detect_content_contention(baseline, sample)
    assert "contention_detected" in result


def test_detect_content_contention_no_contention():
    baseline = {"mean_us": 100, "std_us": 10}
    sample = {"mean_us": 105, "std_us": 12}
    result = NVMeTimingSideChannel.detect_content_contention(baseline, sample)
    assert result["contention_detected"] is False


def test_hmb_eviction_sequence():
    seq = NVMeTimingSideChannel.hmB_eviction_sequence(n_pages=8)
    assert len(seq) > 0


def test_covert_channel_capacity():
    capacity = NVMeTimingSideChannel.covert_channel_capacity(symbol_interval_us=120)
    assert capacity > 0


def test_ctrl_timing_analysis_short():
    times = [100, 200, 150]
    result = NVMeTimingSideChannel.ctrl_timing_analysis(times)
    assert "error" in result


def test_ctrl_timing_analysis_long():
    times = [100 + i for i in range(20)]
    result = NVMeTimingSideChannel.ctrl_timing_analysis(times)
    assert "mean_us" in result


def test_envme_build_dma_attack():
    result = eNVMeIntegration.build_dma_attack_cmd(
        host_phys_addr=0x10000000, size=4096, direction="read"
    )
    assert "host_phys_addr" in result


def test_envme_scan_host_memory():
    result = eNVMeIntegration.scan_host_memory(pattern=b"\x00", chunk_size=512, max_pages=4)
    assert "host_regions" in result


def test_envme_detect_platform():
    data = bytes(4096)
    result = eNVMeIntegration.detect_platform_compatibility(data)
    assert "sgl_supported" in result


def test_nvmeof_icreq():
    pdu = NVMeOverFabrics.build_icreq(hdgst=True, ddgst=False)
    assert len(pdu) > 0


def test_nvmeof_corrupt_icreq_poc():
    pdu = NVMeOverFabrics.build_corrupt_icreq_poc()
    assert len(pdu) > 0


def test_nvmeof_check_vulnerable():
    result = NVMeOverFabrics.check_vulnerable_kernel("6.7")
    assert result["vulnerable"] is True


def test_nvmeof_check_not_vulnerable():
    result = NVMeOverFabrics.check_vulnerable_kernel("6.8")
    assert result["vulnerable"] is False


def test_nvmeof_check_unknown():
    result = NVMeOverFabrics.check_vulnerable_kernel("5.10")
    assert result["vulnerable"] is False


def test_nvmeof_parse_pdu():
    data = b"ICRQ\x02\x01\x00\x00" + b"\x00" * 20
    result = NVMeOverFabrics.parse_nvmetcp_pdu(data)
    assert "pdu_type_name" in result
