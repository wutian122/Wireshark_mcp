"""
数据格式化工具模块

功能说明:
    处理 TShark 原始 JSON 输出到 Pydantic 模型的转换逻辑。
"""
import json
from datetime import datetime
from typing import Any, List, Dict, Union
from schemas.packet import CaptureResultSchema, PacketSchema, CaptureMetadata, FiveTuple

def build_capture_result(
    raw_data: Union[str, List[Dict[str, Any]], Dict[str, Any]],
    limit: int,
    tshark_version: str,
    command: str = ""
) -> CaptureResultSchema:
    """
    构建标准抓包结果对象

    功能: 将 TShark 输出转换为 CaptureResultSchema 对象
    参数: raw_data: TShark 输出; limit: 限制包数; tshark_version: 版本; command: 执行命令
    返回: CaptureResultSchema 对象
    """
    metadata = CaptureMetadata(
        timestamp=datetime.now().isoformat(),
        tshark_version=tshark_version,
        command=command
    )

    if not raw_data:
        return CaptureResultSchema(status="no_data", metadata=metadata, error_message="未捕获到数据")

    packets_data = []
    if isinstance(raw_data, str):
        raw_data = raw_data.strip()
        if not raw_data:
             return CaptureResultSchema(status="no_data", metadata=metadata, error_message="未捕获到数据")
        try:
            parsed = json.loads(raw_data)
            packets_data = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return CaptureResultSchema(status="error", metadata=metadata, error_message="TShark 输出解析失败")
    elif isinstance(raw_data, list):
        packets_data = raw_data
    elif isinstance(raw_data, dict):
        packets_data = [raw_data]

    total_count = len(packets_data)
    truncated = total_count > limit
    final_data = packets_data[:limit] if truncated else packets_data

    packet_models = [_parse_packet(p) for p in final_data]

    return CaptureResultSchema(
        status="success",
        total_packets=total_count,
        returned_packets=len(packet_models),
        truncated=truncated,
        packets=packet_models,
        metadata=metadata
    )

def _parse_packet(pkt_dict: Dict[str, Any]) -> PacketSchema:
    """解析单个数据包字典为模型"""
    source = pkt_dict.get("_source", {})
    layers = source.get("layers", {})
    frame = layers.get("frame", {})

    # 基础信息提取
    timestamp = None
    iface = None
    size = 0

    if "frame.time" in frame:
        timestamp = frame["frame.time"][0] if isinstance(frame["frame.time"], list) else frame["frame.time"]

    if "frame.interface_id_description" in frame:
        iface = frame["frame.interface_id_description"][0] if isinstance(frame["frame.interface_id_description"], list) else frame["frame.interface_id_description"]

    if "frame.len" in frame:
        val = frame["frame.len"][0] if isinstance(frame["frame.len"], list) else frame["frame.len"]
        try:
            size = int(val)
        except (ValueError, TypeError):
            pass

    # 五元组构建
    five_tuple = FiveTuple()
    if "ip" in layers:
        src = layers["ip"].get("ip.src")
        dst = layers["ip"].get("ip.dst")
        five_tuple.src_ip = src[0] if isinstance(src, list) else src
        five_tuple.dst_ip = dst[0] if isinstance(dst, list) else dst
    elif "ipv6" in layers:
        src = layers["ipv6"].get("ipv6.src")
        dst = layers["ipv6"].get("ipv6.dst")
        five_tuple.src_ip = src[0] if isinstance(src, list) else src
        five_tuple.dst_ip = dst[0] if isinstance(dst, list) else dst

    if "tcp" in layers:
        five_tuple.protocol = "TCP"
        src = layers["tcp"].get("tcp.srcport")
        dst = layers["tcp"].get("tcp.dstport")
        try:
            five_tuple.src_port = int(src[0] if isinstance(src, list) else src)
            five_tuple.dst_port = int(dst[0] if isinstance(dst, list) else dst)
        except (ValueError, TypeError):
            pass
    elif "udp" in layers:
        five_tuple.protocol = "UDP"
        src = layers["udp"].get("udp.srcport")
        dst = layers["udp"].get("udp.dstport")
        try:
            five_tuple.src_port = int(src[0] if isinstance(src, list) else src)
            five_tuple.dst_port = int(dst[0] if isinstance(dst, list) else dst)
        except (ValueError, TypeError):
            pass

    return PacketSchema(
        timestamp=str(timestamp) if timestamp else None,
        iface=str(iface) if iface else None,
        size_bytes=size,
        layers=layers,
        five_tuple=five_tuple
    )


def format_json_output(data: Any, max_packets: int, tshark_version: str) -> str:
    """
    兼容旧版 API 的格式化函数

    功能: 包装 build_capture_result，返回 JSON 字符串
    """
    result = build_capture_result(data, max_packets, tshark_version)
    return result.model_dump_json(indent=2)
