import time
from typing import Dict, Any, Optional
from collections import OrderedDict

class ThreatCache:
    """本地威胁情报缓存（LRU + TTL）"""
    
    def __init__(self, max_size: int = 10000, ttl: int = 3600):
        """
        Args:
            max_size: 最大缓存条目数
            ttl: 缓存有效期（秒）
        """
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        """获取缓存值，如果过期则返回 None"""
        if key not in self._cache:
            return None
            
        entry = self._cache[key]
        if time.time() > entry["expire_at"]:
            del self._cache[key]
            return None
            
        # 移动到末尾（最近使用）
        self._cache.move_to_end(key)
        return entry["value"]

    def set(self, key: str, value: Any):
        """设置缓存值"""
        if key in self._cache:
            self._cache.move_to_end(key)
            
        self._cache[key] = {
            "value": value,
            "expire_at": time.time() + self.ttl
        }
        
        if len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def clear(self):
        """清空缓存"""
        self._cache.clear()
