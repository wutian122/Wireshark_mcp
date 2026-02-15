import pytest
from utils.formatting import build_capture_result
from schemas.packet import CaptureResultSchema

def test_build_capture_result_empty():
    """测试空数据处理"""
    res = build_capture_result("", 100, "4.0.0", "cmd")
    assert res.status == "no_data"
    assert res.returned_packets == 0

def test_build_capture_result_valid_json():
    """测试标准 JSON 解析"""
    raw_json = [
        {
            "_source": {
                "layers": {
                    "frame": {
                        "frame.time": "Jan 1, 2023 12:00:00.000000000 UTC",
                        "frame.len": ["60"]
                    },
                    "ip": {
                        "ip.src": ["192.168.1.100"],
                        "ip.dst": ["8.8.8.8"]
                    },
                    "tcp": {
                        "tcp.srcport": ["54321"],
                        "tcp.dstport": ["443"]
                    }
                }
            }
        }
    ]

    res = build_capture_result(raw_json, 10, "4.0.0", "test_cmd")

    assert res.status == "success"
    assert res.total_packets == 1
    assert len(res.packets) == 1

    pkt = res.packets[0]
    assert pkt.five_tuple.src_ip == "192.168.1.100"
    assert pkt.five_tuple.dst_port == 443
    assert pkt.five_tuple.protocol == "TCP"

def test_build_capture_result_malformed_json():
    """测试错误 JSON 处理"""
    res = build_capture_result("{invalid_json}", 10, "4.0.0", "cmd")
    assert res.status == "error"
    assert "解析失败" in res.error_message
