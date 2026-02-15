"""
威胁情报聚合引擎 - 仅使用 AbuseIPDB，支持多 Key 轮询
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from .cache import ThreatCache
from .sources import ThreatSource, AbuseIPDBSource
from .key_manager import APIKeyManager

logger = logging.getLogger(__name__)


class ThreatIntelEngine:
    """
    威胁情报聚合引擎
    
    仅使用 AbuseIPDB 作为威胁情报源：
    - 每日1000次免费查询额度/Key
    - 支持多 Key 轮询扩展额度
    - 支持缓存减少重复查询
    - 支持重试机制
    """

    def __init__(self, config=None):
        """
        初始化威胁情报引擎

        Args:
            config: 配置对象，如果为None则使用默认配置
        """
        from wireshark_mcp.config import config as default_config

        self.config = config or default_config
        self.cache = ThreatCache(ttl=3600)  # 1小时缓存

        # 初始化 API Key 管理器（如果配置了多个 Key）
        self.api_key_manager = None
        if len(self.config.abuseipdb_api_keys) > 1:
            self.api_key_manager = APIKeyManager(self.config)
            logger.info(f"已启用 AbuseIPDB 多 Key 轮询（{len(self.config.abuseipdb_api_keys)} 个 Key）")

        # 初始化威胁情报源
        self.sources: List[ThreatSource] = []
        
        if self.config.abuseipdb_api_key or self.config.abuseipdb_api_keys:
            self.sources.append(
                AbuseIPDBSource(
                    api_key=self.config.abuseipdb_api_key,
                    api_key_manager=self.api_key_manager
                )
            )
            logger.info("已启用 AbuseIPDB 威胁情报源")
        else:
            logger.warning("未配置 AbuseIPDB API Key，威胁情报功能将不可用")
        
    async def check_ip(self, ip: str, retry_count: int = 3) -> Dict[str, Any]:
        """
        检查 IP 威胁信誉
        
        Args:
            ip: 目标 IP 地址
            retry_count: 重试次数
        
        Returns:
            威胁情报字典，包含：
            - ip: 查询的IP地址
            - malicious: 是否为恶意IP
            - risk_score: 风险评分(0-100)
            - sources: 情报源返回的详细信息列表
        """
        # 1. 检查缓存
        cached = self.cache.get(ip)
        if cached:
            logger.debug(f"使用缓存结果: {ip}")
            return cached

        # 2. 查询所有情报源
        results = []
        for source in self.sources:
            result = await self._query_with_retry(source, ip, retry_count)
            if result:
                results.append(result)
        
        # 3. 聚合结果
        final_result = self._aggregate_results(ip, results)
        
        # 4. 写入缓存
        self.cache.set(ip, final_result)
        
        return final_result

    async def _query_with_retry(
        self, 
        source: ThreatSource, 
        ip: str, 
        max_retries: int
    ) -> Optional[Dict[str, Any]]:
        """
        带重试机制的查询方法
        
        Args:
            source: 威胁情报源对象
            ip: 目标IP地址
            max_retries: 最大重试次数
            
        Returns:
            查询结果，失败返回None
        """
        for i in range(max_retries):
            try:
                return await source.query_ip(ip)
            except Exception as e:
                logger.warning(f"[{source.name}] 查询失败 ({i+1}/{max_retries}): {e}")
                if i < max_retries - 1:
                    # 智能退避：如果是速率限制错误，等待更长时间
                    if "rate limit" in str(e).lower() or "429" in str(e):
                        await asyncio.sleep(min(2 ** i, 10))  # 最大10秒
                    else:
                        await asyncio.sleep(1 * (i + 1))
        return None

    def _aggregate_results(self, ip: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        聚合查询结果
        
        Args:
            ip: 查询的IP地址
            results: 各情报源返回的结果列表
            
        Returns:
            聚合后的威胁情报字典
        """
        if not results:
            return {
                "ip": ip,
                "malicious": False,
                "risk_score": 0,
                "sources": []
            }
            
        # 计算风险评分
        risk_scores = []
        for r in results:
            # 优先使用 risk_score 字段
            if "risk_score" in r:
                risk_scores.append(r["risk_score"])
            else:
                # 将 confidence 转换为分数
                conf = r.get("confidence", "unknown")
                score = 0
                if conf == "high":
                    score = 90
                elif conf == "medium":
                    score = 70
                elif conf == "low":
                    score = 50
                risk_scores.append(score)

        return {
            "ip": ip,
            "malicious": True,
            "risk_score": max(risk_scores, default=0),
            "sources": results
        }
    
    def get_key_stats(self) -> Optional[Dict[str, Any]]:
        """
        获取 API Key 统计信息
        
        Returns:
            Key 统计信息字典，如果未启用轮询则返回 None
        """
        if self.api_key_manager:
            return self.api_key_manager.get_key_stats()
        return None


# 全局单例
_engine = None


def get_engine() -> ThreatIntelEngine:
    """
    获取威胁情报引擎单例
    
    Returns:
        ThreatIntelEngine 实例
    """
    global _engine
    if _engine is None:
        _engine = ThreatIntelEngine()
    return _engine
