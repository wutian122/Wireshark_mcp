from schemas.packet import PacketSchema, FiveTuple, CaptureResultSchema
import pytest
from pydantic import ValidationError

def test_five_tuple_creation():
    """测试五元组创建与验证"""
    ft = FiveTuple(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol="TCP"
    )
    assert ft.src_ip == "192.168.1.1"
    assert ft.key == "TCP 192.168.1.1:12345 -> 10.0.0.1:80"

def test_packet_schema_validation():
    """测试数据包模型验证"""
    # 有效数据
    data = {
        "timestamp": "2023-01-01T12:00:00",
        "iface": "eth0",
        "size_bytes": 128,
        "layers": {"frame": {}, "ip": {}},
        "five_tuple": {
            "src_ip": "1.1.1.1",
            "dst_ip": "2.2.2.2",
            "protocol": "UDP"
        }
    }
    pkt = PacketSchema(**data)
    assert pkt.size_bytes == 128
    assert pkt.five_tuple.protocol == "UDP"

    # 无效数据 (size_bytes 必须 >= 0)
    with pytest.raises(ValidationError):
        data["size_bytes"] = -1
        PacketSchema(**data)

def test_capture_result_schema():
    """测试捕获结果模型"""
    res = CaptureResultSchema(
        status="success",
        total_packets=10,
        returned_packets=1,
        truncated=True,
        packets=[],
        metadata={
            "timestamp": "now",
            "tshark_version": "4.0.0",
            "command": "tshark -v"
        }
    )
    assert res.status == "success"
    assert res.truncated is True
