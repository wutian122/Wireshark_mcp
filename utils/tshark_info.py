"""
TShark 信息获取工具模块

功能:
    提供获取 TShark 版本、网络接口列表、支持协议列表等基础信息的功能。
"""
import shutil
import os
import re
import logging
from typing import List, Dict, Optional
from wireshark_mcp.config import config
from utils.subproc import run_tshark

logger = logging.getLogger(__name__)


def get_tshark_version(tshark_path: str = None) -> str:
    """
    获取 TShark 版本信息

    Args:
        tshark_path: TShark 可执行文件路径，若为 None 则使用配置默认值

    Returns:
        str: 版本字符串，若获取失败返回 "unknown"
    """
    path = tshark_path or config.tshark_path
    code, out, _ = run_tshark([path, "-v"])
    if code == 0 and out:
        return out.split("\n")[0].strip()
    return "unknown"


def verify_tshark(tshark_path: str = None) -> bool:
    """
    验证 TShark 是否可用及版本兼容性

    Args:
        tshark_path: TShark 可执行文件路径

    Returns:
        bool: 验证是否通过
    """
    path = tshark_path or config.tshark_path

    # 简单的路径存在性检查
    if not shutil.which(path) and not os.path.isfile(path):
        logger.error(f"找不到 tshark: {path}")
        return False

    version_line = get_tshark_version(path)
    logger.info(f"Found tshark: {version_line}")

    # 解析版本号
    match = re.search(r"(\d+\.\d+\.\d+)", version_line)
    if match:
        version = match.group(1)
        if not config.check_version_compatibility(version):
            logger.warning(f"警告: Wireshark 版本 {version} 低于推荐的最低版本 {config.min_version}")
            logger.warning("某些功能可能无法正常工作。建议升级到最新版本。")
    else:
        logger.warning(f"无法解析 Wireshark 版本号: {version_line}")

    return True


def list_interfaces(tshark_path: str = None) -> List[Dict[str, str]]:
    """
    列出可用的网络接口

    Args:
        tshark_path: TShark 可执行文件路径

    Returns:
        List[Dict[str, str]]: 接口列表，每项包含 name 和 description
    """
    path = tshark_path or config.tshark_path
    code, out, err = run_tshark([path, "-D"])

    if code != 0:
        logger.error(f"获取接口列表失败: {err}")
        return []

    interfaces = []
    for line in out.splitlines():
        if line.strip():
            # 格式: "1. 描述 (名称)" 或 "1. \Device\..."
            try:
                parts = line.strip().split(".", 1)
                if len(parts) == 2:
                    idx = parts[0].strip()
                    rest = parts[1].strip()
                    interfaces.append({"name": idx, "description": rest})
            except Exception:
                continue
    return interfaces


def get_best_interface(tshark_path: str = None) -> str:
    """
    智能获取最佳网络接口索引

    策略:
    1. 获取所有可用接口
    2. 优先匹配物理接口关键词 (Ethernet, Wi-Fi, eth, en, wlan)
    3. 排除虚拟/回环接口关键词 (Loopback, Virtual, VMware, Bluetooth)
    4. 如果没有明确的最佳接口，返回列表中的第一个

    Returns:
        str: 最佳接口的索引字符串 (如 "1")，如果获取失败返回 "1"
    """
    interfaces = list_interfaces(tshark_path)
    if not interfaces:
        return "1"

    # 关键词定义 (不区分大小写)
    priority_keywords = ["ethernet", "wi-fi", "wifi", "wlan", "eth", "en"]
    exclude_keywords = ["loopback", "virtual", "vmware", "bluetooth", "adapter for loopback", "tunnel"]

    # 1. 尝试找到符合优先关键词且不包含排除关键词的接口
    for iface in interfaces:
        desc = iface["description"].lower()
        if any(k in desc for k in priority_keywords) and not any(k in desc for k in exclude_keywords):
            logger.info(f"自动选择最佳接口: {iface['name']} - {iface['description']}")
            return iface["name"]

    # 2. 如果没找到，尝试找任何不包含排除关键词的接口
    for iface in interfaces:
        desc = iface["description"].lower()
        if not any(k in desc for k in exclude_keywords):
            logger.info(f"自动选择次优接口: {iface['name']} - {iface['description']}")
            return iface["name"]

    # 3. 如果还是没找到 (例如只有 Loopback)，返回第一个
    first = interfaces[0]["name"]
    logger.info(f"未找到理想接口，使用默认接口: {first}")
    return first


def get_protocols(tshark_path: str = None) -> List[str]:
    """
    获取支持的协议列表

    Args:
        tshark_path: TShark 可执行文件路径

    Returns:
        List[str]: 协议名称列表
    """
    path = tshark_path or config.tshark_path
    code, out, _ = run_tshark([path, "-G", "protocols"])
    if code == 0 and out:
        return out.splitlines()
    return []
