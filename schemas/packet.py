"""
数据包模型定义模块

功能说明:
    定义抓包结果的标准 Pydantic 模型，用于类型安全的数据交换。
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class FiveTuple(BaseModel):
    """
    五元组结构

    功能: 表示网络会话的核心标识信息
    """
    src_ip: Optional[str] = Field(default=None, description="源 IP 地址")
    src_port: Optional[int] = Field(default=None, description="源端口")
    dst_ip: Optional[str] = Field(default=None, description="目的 IP 地址")
    dst_port: Optional[int] = Field(default=None, description="目的端口")
    protocol: Optional[str] = Field(default=None, description="传输层协议 (TCP/UDP)")

class CaptureMetadata(BaseModel):
    """
    抓包元数据

    功能: 记录抓包操作的上下文信息
    """
    timestamp: str = Field(..., description="执行时间")
    tshark_version: str = Field(..., description="TShark 版本")
    command: Optional[str] = Field(default=None, description="执行的命令")
    duration: Optional[float] = Field(default=None, description="抓包持续时间")

class PacketSchema(BaseModel):
    """
    单个数据包模型

    功能: 统一表示抓到的每个数据包及其详细信息
    """
    timestamp: Optional[str] = Field(default=None, description="捕获时间戳")
    iface: Optional[str] = Field(default=None, description="捕获接口")
    size_bytes: Optional[int] = Field(default=None, description="包大小(字节)")
    payload_hex: Optional[str] = Field(default=None, description="负载十六进制数据")
    layers: Optional[Dict[str, Any]] = Field(default=None, description="协议层详细数据")
    five_tuple: Optional[FiveTuple] = Field(default=None, description="五元组信息")

class CaptureResultSchema(BaseModel):
    """
    抓包结果集合模型

    功能: 表示一次抓包或分析操作的完整结果，包含状态、统计和数据列表
    """
    status: str = Field(..., description="操作状态 (success/error/no_data)")
    error_message: Optional[str] = Field(default=None, description="错误信息（如有）")
    total_packets: int = Field(default=0, description="捕获/解析的总包数")
    returned_packets: int = Field(default=0, description="实际返回的包数")
    truncated: bool = Field(default=False, description="结果是否因限制而被截断")
    packets: List[PacketSchema] = Field(default_factory=list, description="数据包列表")
    metadata: CaptureMetadata = Field(..., description="操作元数据")
