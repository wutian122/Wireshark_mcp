"""
Wireshark MCP 配置模块

仅支持 AbuseIPDB 威胁情报源，包含多 API Key 轮询配置。
支持从环境变量加载配置，增强安全性。
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import yaml
from pydantic import BaseModel, Field


class ThreatIntelConfig(BaseModel):
    """
    威胁情报配置模型 - 仅 AbuseIPDB
    """
    abuseipdb_api_key: str = Field(default="", description="AbuseIPDB API Key（单个）")
    abuseipdb_api_keys: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="AbuseIPDB 多 API Key 轮询配置"
    )
    api_key_rotation: Dict[str, Any] = Field(
        default_factory=lambda: {
            "strategy": "smart",  # smart/round_robin/weighted
            "health_check_interval": 300,
            "failure_threshold": 3,
            "recovery_check_interval": 600,
            "rate_limit_backoff": 3600
        },
        description="API Key 轮换策略配置"
    )


class WiresharkConfig(BaseModel):
    """
    Wireshark/TShark 配置模型
    """
    default_interface: str = Field(default="9", description="默认抓包接口")
    min_version: str = Field(default="3.0.0", description="TShark 最低版本要求")
    tshark_path: str = Field(default="tshark", description="TShark 可执行文件路径")


class AppConfig(BaseModel):
    """
    应用全局配置模型
    """
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    wireshark: WiresharkConfig = Field(default_factory=WiresharkConfig)
    server: Dict[str, Any] = Field(default_factory=lambda: {"host": "127.0.0.1", "port": 3000})


class Config:
    """
    配置管理器（单例模式）

    配置加载优先级（由高到低）：
    1. 环境变量 (ENV)
    2. config.yaml
    3. config.json
    4. 默认值
    """
    _instance = None
    _model: AppConfig = None

    def __init__(self) -> None:
        """
        初始化配置管理器
        """
        # 定位配置文件路径
        base_dir = Path(__file__).resolve().parent.parent
        self.config_json = base_dir / "config.json"
        self.config_yaml = base_dir / "config.yaml"

        self.data = self._load_config()
        # 使用 Pydantic 模型验证和管理配置
        self._model = AppConfig(**self.data)

    @classmethod
    def get_instance(cls) -> 'Config':
        """
        获取配置单例实例

        Returns:
            Config: 配置管理器单例
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_config(self) -> Dict[str, Any]:
        """
        加载配置文件并合并

        Returns:
            Dict[str, Any]: 合并后的配置字典
        """
        config = self._default_config()

        # 1. 尝试加载 config.yaml (优先级高于 json)
        if self.config_yaml.exists():
            try:
                with open(self.config_yaml, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # 简单的环境变量替换支持 (仅用于替换 ${VAR} 格式)
                    # 注意：这只是简单的字符串替换，不是完整的 shell 变量扩展
                    for key, value in os.environ.items():
                        content = content.replace(f"${{{key}}}", value)

                    yaml_config = yaml.safe_load(content)
                    if yaml_config:
                        self._deep_update(config, yaml_config)
            except Exception as e:
                print(f"警告: 加载 config.yaml 失败: {e}")

        # 2. 尝试加载 config.json
        elif self.config_json.exists():
            try:
                with open(self.config_json, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    self._deep_update(config, file_config)
            except Exception:
                pass

        # 3. 环境变量覆盖 (最高优先级)
        self._apply_env_vars(config)

        return config

    def _deep_update(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """
        递归合并字典

        Args:
            base_dict: 基础字典 (将被修改)
            update_dict: 更新字典
        """
        for key, value in update_dict.items():
            if isinstance(value, dict) and key in base_dict and isinstance(base_dict[key], dict):
                self._deep_update(base_dict[key], value)
            else:
                base_dict[key] = value

    def _apply_env_vars(self, config: Dict[str, Any]) -> None:
        """
        应用环境变量覆盖配置

        支持的环境变量:
        - ABUSEIPDB_API_KEY: 覆盖 threat_intel.abuseipdb_api_key
        - ABUSEIPDB_API_KEYS_JSON: JSON字符串，覆盖 threat_intel.abuseipdb_api_keys
        - WIRESHARK_DEFAULT_INTERFACE: 覆盖 wireshark.default_interface
        - WIRESHARK_TSHARK_PATH: 覆盖 wireshark.tshark_path
        - MCP_SERVER_HOST: 覆盖 server.host
        - MCP_SERVER_PORT: 覆盖 server.port
        """
        # AbuseIPDB API Key (Single)
        env_abuseipdb = os.environ.get("ABUSEIPDB_API_KEY")
        if env_abuseipdb:
            config["threat_intel"]["abuseipdb_api_key"] = env_abuseipdb

        # AbuseIPDB API Keys (List via JSON)
        env_abuseipdb_list = os.environ.get("ABUSEIPDB_API_KEYS_JSON")
        if env_abuseipdb_list:
            try:
                keys_list = json.loads(env_abuseipdb_list)
                if isinstance(keys_list, list):
                    config["threat_intel"]["abuseipdb_api_keys"] = keys_list
            except json.JSONDecodeError:
                print("警告: 环境变量 ABUSEIPDB_API_KEYS_JSON 格式错误")

        # Wireshark 接口
        env_interface = os.environ.get("WIRESHARK_DEFAULT_INTERFACE")
        if env_interface:
            config["wireshark"]["default_interface"] = env_interface

        # TShark 路径
        env_tshark = os.environ.get("WIRESHARK_TSHARK_PATH")
        if env_tshark:
            config["wireshark"]["tshark_path"] = env_tshark

        # Server Config
        env_host = os.environ.get("MCP_SERVER_HOST")
        if env_host:
            config["server"]["host"] = env_host

        env_port = os.environ.get("MCP_SERVER_PORT")
        if env_port:
            try:
                config["server"]["port"] = int(env_port)
            except ValueError:
                pass

    def _default_config(self) -> Dict[str, Any]:
        """
        生成默认配置

        Returns:
            Dict[str, Any]: 默认配置字典
        """
        return {
            "threat_intel": {
                "abuseipdb_api_key": "",
                "abuseipdb_api_keys": [],
                "api_key_rotation": {
                    "strategy": "smart",
                    "health_check_interval": 300,
                    "failure_threshold": 3,
                    "recovery_check_interval": 600,
                    "rate_limit_backoff": 3600
                }
            },
            "wireshark": {
                "default_interface": "9",
                "min_version": "3.0.0",
                "tshark_path": "tshark"
            },
            "server": {
                "host": "127.0.0.1",
                "port": 3000
            }
        }

    @property
    def abuseipdb_api_key(self) -> str:
        """获取 AbuseIPDB API Key（单个）"""
        return self._model.threat_intel.abuseipdb_api_key

    @property
    def abuseipdb_api_keys(self) -> List[Dict[str, Any]]:
        """
        获取 AbuseIPDB 多 API Key 配置

        如果未配置多Key，但有单Key，自动转换为列表格式，
        确保返回统一的列表结构。
        """
        keys = self._model.threat_intel.abuseipdb_api_keys

        # 向后兼容：如果未配置多Key，但有单Key，自动转换
        if not keys and self.abuseipdb_api_key:
            keys = [{
                "key": self.abuseipdb_api_key,
                "name": "default",
                "enabled": True,
                "weight": 100
            }]
        return keys

    @property
    def default_interface(self) -> str:
        """获取默认抓包接口"""
        return self._model.wireshark.default_interface

    @property
    def min_version(self) -> str:
        """获取 TShark 最低版本要求"""
        return self._model.wireshark.min_version

    @property
    def tshark_path(self) -> str:
        """获取 TShark 路径"""
        return self._model.wireshark.tshark_path

    @property
    def rotation_config(self) -> Dict[str, Any]:
        """获取 API Key 轮换配置"""
        return self._model.threat_intel.api_key_rotation

    def check_version_compatibility(self, current_version: str) -> bool:
        """
        检查 TShark 版本兼容性

        Args:
            current_version: 当前 TShark 版本字符串

        Returns:
            bool: 是否兼容
        """
        try:
            min_v = self.min_version.split('.')
            curr_v = current_version.split('.')

            # 补齐版本号位数
            while len(min_v) < 3:
                min_v.append('0')
            while len(curr_v) < 3:
                curr_v.append('0')

            min_v_ints = [int(x) for x in min_v[:3]]
            curr_v_ints = [int(x) for x in curr_v[:3]]

            return curr_v_ints >= min_v_ints
        except Exception:
            return True


# 全局配置单例
config = Config.get_instance()
