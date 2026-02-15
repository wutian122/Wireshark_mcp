"""
API Key管理器 - 智能轮换和健康状态管理（AbuseIPDB专用）

支持多种轮换策略：智能、轮询、加权
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
from enum import Enum
import random

logger = logging.getLogger(__name__)


class KeyStatus(Enum):
    """API Key状态枚举"""
    ACTIVE = "active"
    RATE_LIMITED = "rate_limited"
    FAILED = "failed"
    RECOVERING = "recovering"


@dataclass
class APIKeyState:
    """API Key状态信息"""
    key: str
    name: str
    enabled: bool = True
    weight: int = 100
    status: KeyStatus = KeyStatus.ACTIVE
    failure_count: int = 0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    last_rate_limit: Optional[datetime] = None
    reset_time: Optional[datetime] = None
    request_count: int = 0
    success_count: int = 0

    @property
    def success_rate(self) -> float:
        """成功率"""
        if self.request_count == 0:
            return 1.0
        return self.success_count / self.request_count

    @property
    def is_available(self) -> bool:
        """Key是否可用"""
        if not self.enabled:
            return False

        now = datetime.now(timezone.utc)

        # 检查速率限制状态
        if self.status == KeyStatus.RATE_LIMITED:
            if self.reset_time and now >= self.reset_time:
                self.status = KeyStatus.ACTIVE
                self.failure_count = 0
                logger.info(f"API Key {self.name} 速率限制已解除")
            else:
                return False

        # 检查失败状态
        if self.status == KeyStatus.FAILED:
            if self.last_failure and (now - self.last_failure).seconds >= 600:  # 10分钟后尝试恢复
                self.status = KeyStatus.RECOVERING
                logger.info(f"API Key {self.name} 进入恢复模式")

        return self.status in [KeyStatus.ACTIVE, KeyStatus.RECOVERING]


class APIKeyManager:
    """
    AbuseIPDB API Key 管理器
    
    支持多个 API Key 轮询，每个 Key 每日1000次查询额度
    """

    def __init__(self, config):
        """
        初始化 API Key 管理器

        Args:
            config: Config对象，包含 API Key 配置
        """
        self.config = config
        self.keys: Dict[str, APIKeyState] = {}
        self.current_index = 0
        self.strategy = config.rotation_config.get("strategy", "smart")
        self.failure_threshold = config.rotation_config.get("failure_threshold", 3)
        self._lock = asyncio.Lock()

        # 初始化 API Keys
        self._initialize_keys()

        # 启动健康检查任务
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._health_check_loop())
        except RuntimeError:
            # 如果没有运行中的事件循环，跳过健康检查
            pass

    def _initialize_keys(self):
        """初始化 AbuseIPDB API Keys"""
        for key_config in self.config.abuseipdb_api_keys:
            state = APIKeyState(
                key=key_config["key"],
                name=key_config.get("name", f"key_{len(self.keys)}"),
                enabled=key_config.get("enabled", True),
                weight=key_config.get("weight", 100)
            )

            # 解析 reset_time
            if key_config.get("reset_time"):
                try:
                    state.reset_time = datetime.fromisoformat(
                        key_config["reset_time"].replace('Z', '+00:00')
                    )
                except Exception as e:
                    logger.warning(f"解析 reset_time 失败: {e}")

            self.keys[state.name] = state
            
        logger.info(f"已初始化 {len(self.keys)} 个 AbuseIPDB API Key")

    async def get_next_key(self) -> Optional[str]:
        """获取下一个可用的 API Key"""
        async with self._lock:
            return self._select_key()

    def _select_key(self) -> Optional[str]:
        """根据策略选择 API Key"""
        available_keys = [k for k in self.keys.values() if k.is_available]

        if not available_keys:
            logger.warning("没有可用的 AbuseIPDB API Key")
            return None

        if self.strategy == "round_robin":
            return self._round_robin_select(available_keys)
        elif self.strategy == "weighted":
            return self._weighted_select(available_keys)
        else:  # smart
            return self._smart_select(available_keys)

    def _round_robin_select(self, keys: List[APIKeyState]) -> str:
        """轮询选择"""
        key = keys[self.current_index % len(keys)]
        self.current_index += 1
        return key.key

    def _weighted_select(self, keys: List[APIKeyState]) -> str:
        """加权随机选择"""
        total_weight = sum(k.weight for k in keys)
        r = random.uniform(0, total_weight)

        current = 0
        for key in keys:
            current += key.weight
            if r <= current:
                return key.key

        return keys[-1].key

    def _smart_select(self, keys: List[APIKeyState]) -> str:
        """智能选择：综合考虑成功率、权重、最后使用时间"""
        now = datetime.now(timezone.utc)

        def score(key: APIKeyState) -> float:
            s = 0

            # 成功率权重 (0-40分)
            s += key.success_rate * 40

            # 权重分 (0-30分)
            s += (key.weight / 100) * 30

            # 最后使用时间分 (0-30分，越久未使用分数越高)
            if key.last_success:
                time_diff = (now - key.last_success).seconds
                s += min(time_diff / 3600, 1) * 30  # 1小时满分
            else:
                s += 30  # 从未使用的Key优先

            return s

        return max(keys, key=score).key

    async def record_success(self, api_key: str):
        """记录成功请求"""
        async with self._lock:
            for key in self.keys.values():
                if key.key == api_key:
                    key.last_success = datetime.now(timezone.utc)
                    key.success_count += 1
                    key.request_count += 1
                    key.failure_count = 0  # 重置失败计数

                    # 如果在恢复状态，恢复为活跃
                    if key.status == KeyStatus.RECOVERING:
                        key.status = KeyStatus.ACTIVE
                        logger.info(f"API Key {key.name} 已恢复")
                    break

    async def record_failure(self, api_key: str, error: str):
        """记录失败请求"""
        async with self._lock:
            for key in self.keys.values():
                if key.key == api_key:
                    key.last_failure = datetime.now(timezone.utc)
                    key.request_count += 1
                    key.failure_count += 1

                    # 检查是否超过失败阈值
                    if key.failure_count >= self.failure_threshold:
                        key.status = KeyStatus.FAILED
                        logger.warning(f"API Key {key.name} 已标记为失败")

                    # 检查是否是速率限制错误
                    if self._is_rate_limit_error(error):
                        key.status = KeyStatus.RATE_LIMITED
                        key.last_rate_limit = datetime.now(timezone.utc)
                        # 设置重置时间（1小时后）
                        backoff_seconds = self.config.rotation_config.get("rate_limit_backoff", 3600)
                        key.reset_time = datetime.now(timezone.utc).replace(
                            microsecond=0
                        ) + timedelta(seconds=backoff_seconds)
                        logger.warning(f"API Key {key.name} 触发速率限制，{backoff_seconds}秒后恢复")
                    break

    def _is_rate_limit_error(self, error: str) -> bool:
        """判断是否是速率限制错误"""
        rate_limit_indicators = [
            "rate limit",
            "quota exceeded",
            "too many requests",
            "429",
            "请求过于频繁",
            "超过配额",
            "频率限制",
            "速率限制"
        ]
        error_lower = error.lower()
        return any(indicator in error_lower for indicator in rate_limit_indicators)

    async def _health_check_loop(self):
        """健康检查循环"""
        interval = self.config.rotation_config.get("health_check_interval", 300)

        while True:
            try:
                await asyncio.sleep(interval)
                await self._perform_health_check()
            except Exception as e:
                logger.error(f"健康检查异常: {e}")

    async def _perform_health_check(self):
        """执行健康检查"""
        now = datetime.now(timezone.utc)

        for key in self.keys.values():
            # 检查长时间未使用的Key
            if key.last_success and (now - key.last_success).seconds > 3600:
                if key.status == KeyStatus.ACTIVE:
                    logger.debug(f"API Key {key.name} 长时间未使用")

    def get_key_stats(self) -> Dict[str, Dict[str, Any]]:
        """获取所有 Key 的统计信息"""
        stats = {}
        for name, key in self.keys.items():
            stats[name] = {
                "status": key.status.value,
                "success_rate": f"{key.success_rate:.2%}",
                "request_count": key.request_count,
                "success_count": key.success_count,
                "failure_count": key.failure_count,
                "last_success": key.last_success.isoformat() if key.last_success else None,
                "enabled": key.enabled,
                "weight": key.weight
            }
        return stats