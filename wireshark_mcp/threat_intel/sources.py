"""
威胁情报源模块 - 仅保留 AbuseIPDB 接口，支持多 Key 轮询

AbuseIPDB 提供每日1000次免费查询额度，足够日常威胁检测需求
通过多 API Key 轮询可以扩展查询额度
"""

import httpx
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .key_manager import APIKeyManager

logger = logging.getLogger(__name__)


class ThreatSource(ABC):
    """
    威胁情报源基类
    
    所有威胁情报源都需要继承此类并实现query_ip方法
    """
    
    def __init__(self, name: str):
        """
        初始化威胁情报源
        
        Args:
            name: 情报源名称
        """
        self.name = name

    @abstractmethod
    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        查询 IP 信誉
        
        Args:
            ip: 目标IP地址
            
        Returns:
            威胁情报结果字典，如无威胁则返回None
        """
        pass


class AbuseIPDBSource(ThreatSource):
    """
    AbuseIPDB 威胁情报源 - 支持多 API Key 轮询
    
    AbuseIPDB 是一个免费的IP信誉检测服务：
    - 免费额度：每日1000次查询/Key
    - 注册地址：https://www.abuseipdb.com/register
    - 获取API Key：登录后点击 API -> Create Key
    - 支持多 Key 轮询扩展额度
    """
    
    def __init__(self, api_key: str = None, api_key_manager: Optional["APIKeyManager"] = None):
        """
        初始化 AbuseIPDB 情报源
        
        Args:
            api_key: 单个 AbuseIPDB API Key（向后兼容）
            api_key_manager: API Key 管理器（支持多 Key 轮询）
        """
        super().__init__("AbuseIPDB")
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.api_key_manager = api_key_manager
        
        # 向后兼容：如果没有提供manager，使用单个Key
        if not self.api_key_manager:
            self.api_key = api_key
            self.use_rotation = False
        else:
            self.use_rotation = True
        
    async def query_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        查询 IP 在 AbuseIPDB 中的信誉记录 - 支持 API Key 轮询
        
        Args:
            ip: 目标IP地址
            
        Returns:
            威胁情报结果字典
        """
        if self.use_rotation:
            return await self._query_with_rotation(ip)
        else:
            return await self._query_with_single_key(ip)
    
    async def _query_with_rotation(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        使用 API Key 轮询查询
        
        Args:
            ip: 目标IP地址
            
        Returns:
            威胁情报结果字典
        """
        max_attempts = len(self.api_key_manager.keys) * 2  # 每个Key最多尝试2次
        last_error = None

        for attempt in range(max_attempts):
            api_key = await self.api_key_manager.get_next_key()
            if not api_key:
                logger.warning("没有可用的 AbuseIPDB API Key")
                break

            try:
                result = await self._execute_query(ip, api_key)
                await self.api_key_manager.record_success(api_key)
                return result

            except Exception as e:
                last_error = str(e)
                await self.api_key_manager.record_failure(api_key, last_error)
                logger.warning(f"AbuseIPDB API Key 查询失败，尝试下一个: {e}")

                # 如果是速率限制，等待后重试
                if self.api_key_manager._is_rate_limit_error(last_error):
                    await asyncio.sleep(1)

        logger.error(f"所有 AbuseIPDB API Key 都已失败，最后错误: {last_error}")
        return None

    async def _query_with_single_key(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        使用单个 API Key 查询（向后兼容）
        
        Args:
            ip: 目标IP地址
            
        Returns:
            威胁情报结果字典
        """
        if not self.api_key:
            logger.warning("未配置 AbuseIPDB API Key，跳过查询")
            return None

        return await self._execute_query(ip, self.api_key)
        
    async def _execute_query(self, ip: str, api_key: str) -> Optional[Dict[str, Any]]:
        """
        执行 AbuseIPDB API 查询
        
        Args:
            ip: 目标IP地址
            api_key: API Key
            
        Returns:
            威胁情报结果字典
        """
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90  # 查询最近90天的记录
        }
        
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self.base_url, 
                headers=headers, 
                params=params, 
                timeout=10.0
            )
            
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                
                # 根据评分判断置信度
                confidence = "low"
                if score > 80:
                    confidence = "high"
                elif score > 50:
                    confidence = "medium"
                
                # 如果评分为0，说明没有威胁记录
                if score == 0:
                    return None
                
                return {
                    "source": self.name,
                    "ip": ip,
                    "malicious": score > 0,
                    "confidence": confidence,
                    "tags": data.get("reports", [])[:5],  # 只取前5条报告
                    "risk_score": score,
                    "details": {
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "total_reports": data.get("totalReports", 0),
                        "last_reported_at": data.get("lastReportedAt")
                    }
                }
                
            elif resp.status_code == 429:
                raise Exception("请求频率超限(429)，触发速率限制")
                
            elif resp.status_code == 401:
                raise Exception("API Key 无效(401)")
                
            elif resp.status_code == 422:
                logger.warning(f"AbuseIPDB: 无效的IP地址格式 - {ip}")
                return None
            else:
                raise Exception(f"HTTP错误: {resp.status_code}")
                
        return None
