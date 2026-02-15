from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ConversationSchema(BaseModel):
    """TCP/UDP 会话模型

    功能: 统一表示一条会话的端点与统计信息
    参数: 无
    返回: 会话对象用于 JSON 输出
    """
    proto: str
    src: str
    sport: Optional[int] = Field(default=None)
    dst: str
    dport: Optional[int] = Field(default=None)
    start_ts: Optional[str] = Field(default=None)
    end_ts: Optional[str] = Field(default=None)
    duration_ms: Optional[int] = Field(default=None)
    packets: int
    bytes: int
    flags: Optional[Dict[str, Any]] = Field(default=None)

