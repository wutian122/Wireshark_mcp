from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class CredentialSchema(BaseModel):
    """凭证提取模型

    功能: 表示从网络流量中提取的认证信息
    参数: 无
    返回: 标准化凭证对象
    """
    protocol: str
    username: Optional[str] = Field(default=None)
    password: Optional[str] = Field(default=None)
    src: Optional[str] = Field(default=None)
    dst: Optional[str] = Field(default=None)
    timestamp: Optional[str] = Field(default=None)
    evidence_packet_ids: List[int] = Field(default_factory=list)

