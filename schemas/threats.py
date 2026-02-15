from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ThreatMatch(BaseModel):
    """威胁匹配详情

    功能: 表示一次黑名单命中的规则与来源
    参数: 无
    返回: 匹配详情对象
    """
    rule: str
    signature: Optional[str] = Field(default=None)
    first_seen: Optional[str] = Field(default=None)
    last_seen: Optional[str] = Field(default=None)


class ThreatEntity(BaseModel):
    """威胁实体（IP/域名/URL）

    功能: 表示被检测的实体及其命中情况
    参数: 无
    返回: 威胁实体对象
    """
    type: str
    value: str
    matches: List[ThreatMatch] = Field(default_factory=list)


class ThreatReportSchema(BaseModel):
    """黑名单检测报告

    功能: 汇总检测来源、实体与结论
    参数: 无
    返回: 标准化威胁报告
    """
    source: str
    severity: str
    confidence: float
    entities: List[ThreatEntity] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IOCReportSchema(BaseModel):
    """单 IP IOC 报告

    功能: 描述单 IP 的命中详情
    参数: 无
    返回: 标准化 IOC 报告
    """
    ip: str
    severity: str
    confidence: float
    matches: List[ThreatMatch] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

