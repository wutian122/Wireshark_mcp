import pytest
from unittest.mock import patch, MagicMock
from capture.offline import analyze_pcap
import json

# 模拟 TShark 的标准输出 JSON
MOCK_TSHARK_OUTPUT = json.dumps([
    {
        "_source": {
            "layers": {
                "frame": {"frame.len": ["100"]},
                "ip": {"ip.src": ["10.0.0.1"], "ip.dst": ["10.0.0.2"]}
            }
        }
    }
])

@patch("capture.offline.run_tshark")
@patch("capture.offline.os.path.exists")
def test_analyze_pcap_success(mock_exists, mock_run_tshark):
    """测试离线分析成功场景"""
    # 模拟文件存在
    mock_exists.return_value = True

    # 模拟 run_tshark 返回:
    # 第一次调用 (版本检测): code=0, out="TShark 4.0.0", err=""
    # 第二次调用 (实际分析): code=0, out=MOCK_TSHARK_OUTPUT, err=""
    mock_run_tshark.side_effect = [
        (0, "TShark (Wireshark) 4.0.0 (v4.0.0)", ""),
        (0, MOCK_TSHARK_OUTPUT, "")
    ]

    result = analyze_pcap(
        file_path="test.pcap",
        display_filter="ip",
        limit=10,
        tshark_path="tshark"
    )

    assert result.status == "success"
    assert result.total_packets == 1
    assert result.packets[0].five_tuple.src_ip == "10.0.0.1"

    # 验证 run_tshark 调用参数
    assert mock_run_tshark.call_count == 2
    args, kwargs = mock_run_tshark.call_args
    cmd = args[0]
    assert "test.pcap" in cmd
    assert "-Y" in cmd
    assert "ip" in cmd

@patch("capture.offline.os.path.exists")
def test_analyze_pcap_file_not_found(mock_exists):
    """测试文件不存在场景"""
    mock_exists.return_value = False

    with patch("capture.offline.run_tshark", return_value=(0, "v4.0", "")):
        result = analyze_pcap("missing.pcap", "", 10, "tshark")

    assert result.status == "error"
    assert "找不到文件" in result.error_message

@patch("capture.offline.run_tshark")
@patch("capture.offline.os.path.exists")
def test_analyze_pcap_execution_error(mock_exists, mock_run_tshark):
    """测试 TShark 执行失败场景"""
    mock_exists.return_value = True

    mock_run_tshark.side_effect = [
        (0, "v4.0", ""), # 版本检测
        (1, "", "Sample Error") # 分析失败
    ]

    result = analyze_pcap("test.pcap", "", 10, "tshark")

    assert result.status == "error"
    assert "Sample Error" in result.error_message
