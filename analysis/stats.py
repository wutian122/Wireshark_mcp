from typing import List, Dict, Any
from schemas.stats import SummaryStatsSchema, ProtocolStat


def build_summary_stats(packets: List[Dict[str, Any]]) -> SummaryStatsSchema:
    """生成协议汇总统计

    功能: 根据包列表聚合协议占比、字节数与包数
    参数: packets: 解析后的包对象列表（tshark json）
    返回: SummaryStatsSchema
    """
    total_packets = len(packets)
    proto_counter: Dict[str, Dict[str, int]] = {}

    total_bytes = 0
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        frame_layer = layers.get("frame", {})
        frame_len = frame_layer.get("frame.len")
        size = int(frame_len[0]) if isinstance(frame_len, list) and frame_len else 0
        total_bytes += size
        for key in layers.keys():
            proto = key.split(".")[0]
            if proto not in proto_counter:
                proto_counter[proto] = {"packets": 0, "bytes": 0}
            proto_counter[proto]["packets"] += 1
            proto_counter[proto]["bytes"] += size

    stats = [
        ProtocolStat(protocol=k, packets=v["packets"], bytes=v["bytes"], ratio=(v["packets"] / total_packets * 100.0 if total_packets else 0.0))
        for k, v in proto_counter.items()
    ]

    return SummaryStatsSchema(total_packets=total_packets, total_bytes=total_bytes, protocols=stats, metadata={})

