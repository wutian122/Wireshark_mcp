from typing import Dict, Any, List
from pydantic import BaseModel, Field


class ProtocolStat(BaseModel):
    """单协议统计

    功能: 描述某协议的包数、字节数与占比
    参数: 无
    返回: 协议统计对象
    """
    protocol: str
    packets: int
    bytes: int
    ratio: float


class SummaryStatsSchema(BaseModel):
    """协议汇总统计

    功能: 汇总各协议占比与总体指标
    参数: 无
    返回: 汇总统计对象
    """
    total_packets: int
    total_bytes: int
    protocols: List[ProtocolStat] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

