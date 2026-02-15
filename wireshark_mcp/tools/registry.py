"""
MCP 工具注册器模块

功能说明:
    集中管理 MCP 工具的注册逻辑，提供更清晰的工具组织结构和更好的可维护性。

工具分类:
    - 基础工具: list_interfaces, get_protocols, verify_environment
    - 抓包工具: capture_live, capture_packets
    - 自动化工具: scan_network_threats (NEW)
    - 分析工具: analyze_pcap, analyze_pcap_full, extract_fields, analyze_protocols, analyze_errors
    - 统计工具: get_packet_statistics, get_summary_stats, get_conversations
    - 安全工具: check_ip_threats, check_threats, extract_credentials
"""
import asyncio
import json
import logging
import ipaddress
from typing import Dict, List, Any, Optional, TYPE_CHECKING, Set

from mcp.server.fastmcp import FastMCP

if TYPE_CHECKING:
    from wireshark_mcp.server import WiresharkMCP

from capture.live import capture_packets as live_capture_packets
from capture.offline import analyze_pcap as offline_analyze_pcap
from analysis.stats import build_summary_stats
from analysis.conversations import get_conversations as conv_get
from analysis.credentials import extract_credentials_from_packets
from wireshark_mcp.threat_intel import get_engine
from wireshark_mcp.config import config
import utils.tshark_info as tshark_info

logger = logging.getLogger(__name__)


class MCPToolRegistry:
    """
    MCP 工具注册器

    功能: 集中管理所有 MCP 工具的注册，按功能分类组织工具
    """

    def __init__(self, wireshark: "WiresharkMCP", mcp: FastMCP):
        self.wireshark = wireshark
        self.mcp = mcp

    def register_all(self) -> None:
        """注册所有工具"""
        self.register_basic_tools()
        self.register_capture_tools()
        self.register_automation_tools()  # NEW
        self.register_analysis_tools()
        self.register_statistics_tools()
        self.register_security_tools()
        logger.info("所有 MCP 工具注册完成")

    def register_basic_tools(self) -> None:
        """注册基础工具"""
        mcp = self.mcp

        @mcp.tool()
        def list_interfaces() -> List[Dict[str, str]]:
            """列出所有可用的网络接口"""
            return tshark_info.list_interfaces(config.tshark_path)

        @mcp.tool()
        def get_protocols() -> List[str]:
            """获取支持的协议列表"""
            return tshark_info.get_protocols(config.tshark_path)

        @mcp.tool()
        def verify_environment() -> Dict[str, Any]:
            """验证 TShark 环境和 API Key 配置状态"""
            tshark_ok = tshark_info.verify_tshark(config.tshark_path)
            tshark_ver = tshark_info.get_tshark_version(config.tshark_path)
            best_iface = tshark_info.get_best_interface(config.tshark_path)

            engine = get_engine()
            key_stats = engine.get_key_stats()

            return {
                "tshark": {
                    "available": tshark_ok,
                    "version": tshark_ver,
                    "path": config.tshark_path
                },
                "network": {
                    "best_interface": best_iface
                },
                "threat_intel": {
                    "abuseipdb_enabled": bool(config.abuseipdb_api_key or config.abuseipdb_api_keys),
                    "key_stats": key_stats
                }
            }

    def register_capture_tools(self) -> None:
        """注册抓包工具"""
        mcp = self.mcp

        @mcp.tool()
        def capture_live(
            interface: str = "",
            duration: int = 10,
            filter: str = "",
            max_packets: int = 100
        ) -> str:
            """简易实时抓包 (自动选择最佳接口)"""
            if not interface:
                interface = tshark_info.get_best_interface(config.tshark_path)
                logger.info(f"自动选择接口: {interface}")

            return live_capture_packets(
                interface=interface,
                duration=duration,
                bpf_filter=filter,
                display_filter="",
                limit=max_packets,
                tshark_path=config.tshark_path
            ).model_dump_json(indent=2)

        @mcp.tool()
        def capture_packets(
            interface: str = "",
            duration: int = 10,
            bpf_filter: str = "",
            display_filter: str = "",
            limit: int = 100,
            ssl_keylog_file: str = "",
            enable_reassembly: bool = True
        ) -> str:
            """高级实时抓包 (自动选择最佳接口)"""
            if not interface:
                interface = tshark_info.get_best_interface(config.tshark_path)
                logger.info(f"自动选择接口: {interface}")

            return live_capture_packets(
                interface, duration, bpf_filter, display_filter,
                limit, config.tshark_path, ssl_keylog_file, enable_reassembly
            ).model_dump_json(indent=2)

    def register_automation_tools(self) -> None:
        """注册自动化复合工具 (Phase 2)"""
        mcp = self.mcp

        @mcp.tool()
        async def scan_network_threats(
            duration: int = 30,
            max_packets: int = 1000
        ) -> str:
            """
            [一键式] 扫描当前网络威胁 (自动抓包 -> 提取IP -> 查询情报 -> 生成报告)

            功能:
            1. 自动识别最佳网络接口
            2. 抓取指定时长的实时流量
            3. 提取所有公网 IP 地址
            4. 并发查询 AbuseIPDB 威胁情报
            5. 返回 Markdown 格式的安全评估报告

            Args:
                duration: 抓包持续时间(秒), 默认30秒
                max_packets: 最大分析包数

            Returns:
                str: Markdown 格式的威胁评估报告
            """
            # 1. 自动选择接口
            iface = tshark_info.get_best_interface(config.tshark_path)

            # 2. 执行抓包
            logger.info(f"开始在接口 {iface} 上抓包 {duration} 秒...")
            result = live_capture_packets(
                interface=iface,
                duration=duration,
                bpf_filter="", # 抓取所有流量
                display_filter="",
                limit=max_packets,
                tshark_path=config.tshark_path
            )

            if result.status != "success":
                return f"# 扫描失败\n\n抓包错误: {result.error_message}"

            # 3. 提取公网 IP
            unique_ips = set()
            for pkt in result.packets:
                if not pkt.five_tuple:
                    continue
                for ip_str in [pkt.five_tuple.src_ip, pkt.five_tuple.dst_ip]:
                    if not ip_str: continue
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast):
                            unique_ips.add(str(ip_obj))
                    except ValueError:
                        continue

            if not unique_ips:
                return f"# 扫描完成 (无威胁)\n\n**接口**: {iface}\n**包数**: {len(result.packets)}\n\n未发现公网 IP 通信，仅检测到局域网流量。"

            # 4. 威胁情报查询
            logger.info(f"正在扫描 {len(unique_ips)} 个公网 IP...")
            engine = get_engine()
            tasks = [engine.check_ip(ip) for ip in unique_ips]
            threat_data = await asyncio.gather(*tasks)

            # 5. 生成报告
            malicious_ips = []
            for item in threat_data:
                if item.get('malicious') or item.get('risk_score', 0) > 0:
                    malicious_ips.append(item)

            report = []
            report.append("# 🛡️ 网络威胁扫描报告")
            report.append(f"- **接口**: {iface}")
            report.append(f"- **抓包时长**: {duration}s")
            report.append(f"- **分析包数**: {len(result.packets)}")
            report.append(f"- **公网 IP 数**: {len(unique_ips)}")
            report.append(f"- **发现威胁**: {len(malicious_ips)}")
            report.append("---")

            if not malicious_ips:
                report.append("### ✅ 当前网络环境安全")
                report.append("未发现已知的恶意 IP 地址活动。")
            else:
                report.append("### ⚠️ 发现潜在恶意活动")
                for item in malicious_ips:
                    ip = item['ip']
                    score = item.get('risk_score', 0)
                    report.append(f"#### 🔴 IP: {ip} (风险分: {score})")
                    if 'sources' in item:
                        for src in item['sources']:
                            data = src.get('data', {})
                            country = data.get('countryCode', 'N/A')
                            isp = data.get('isp', 'N/A')
                            reports = data.get('totalReports', 0)
                            report.append(f"- **归属**: {country} | {isp}")
                            report.append(f"- **情报**: 被举报 {reports} 次")
                    report.append("")

            return "\n".join(report)

    def register_analysis_tools(self) -> None:
        """注册分析工具"""
        wireshark = self.wireshark
        mcp = self.mcp

        @mcp.tool()
        def analyze_pcap(
            file_path: str,
            filter: str = "",
            max_packets: int = 100
        ) -> str:
            """分析 pcap 文件"""
            return offline_analyze_pcap(
                file_path=file_path,
                display_filter=filter,
                limit=max_packets,
                tshark_path=config.tshark_path
            ).model_dump_json(indent=2)

        @mcp.tool()
        def analyze_pcap_full(
            file_path: str,
            display_filter: str = "",
            limit: int = 100,
            ssl_keylog_file: str = "",
            enable_reassembly: bool = True
        ) -> str:
            """高级离线 PCAP 分析"""
            return offline_analyze_pcap(
                file_path, display_filter, limit,
                config.tshark_path, ssl_keylog_file, enable_reassembly
            ).model_dump_json(indent=2)

        # 兼容性保留：部分复杂分析暂时仍调用 wireshark 实例方法
        # 后续建议迁移到独立模块
        @mcp.tool()
        def extract_fields(file_path: str, fields: List[str], filter: str = "", max_packets: int = 5000) -> str:
            """
            从 PCAP 文件中提取特定字段信息

            Args:
                file_path: PCAP 文件路径
                fields: 需要提取的字段列表 (如 ["ip.src", "http.host"])
                filter: 显示过滤器
                max_packets: 最大分析包数
            """
            return wireshark.extract_fields(file_path, fields, filter, max_packets)

        @mcp.tool()
        def analyze_protocols(file_path: str, protocol: str = "", max_packets: int = 100) -> str:
            """
            分析特定协议的数据包分布与详情

            Args:
                file_path: PCAP 文件路径
                protocol: 协议名称 (如 "http", "dns")
                max_packets: 最大分析包数
            """
            return wireshark.analyze_protocols(file_path, protocol, max_packets)

        @mcp.tool()
        def analyze_errors(file_path: str, error_type: str = "all", max_packets: int = 5000) -> str:
            """
            分析数据包中的 TCP 错误（重传、乱序等）

            Args:
                file_path: PCAP 文件路径
                error_type: 错误类型 (all, malformed, tcp, duplicate_ack, lost_segment)
                max_packets: 最大分析包数
            """
            return wireshark.analyze_errors(file_path, error_type, max_packets)

    def register_statistics_tools(self) -> None:
        """注册统计工具"""
        wireshark = self.wireshark
        mcp = self.mcp

        @mcp.tool()
        def get_packet_statistics(file_path: str, filter: str = "") -> str:
            """
            获取 PCAP 文件的基础统计信息 (IO, 时间, 大小)

            Args:
                file_path: PCAP 文件路径
                filter: 显示过滤器
            """
            return wireshark.get_packet_statistics(file_path, filter)

        @mcp.tool()
        def get_summary_stats(
            file_path: str,
            display_filter: str = "",
            limit: int = 100
        ) -> str:
            """按协议类型统计流量分布"""
            res = offline_analyze_pcap(file_path, display_filter, limit, config.tshark_path)
            if res.status != "success":
                return json.dumps({"status": "error", "message": res.error_message})

            stats = build_summary_stats(res.packets)
            return stats.model_dump_json(indent=2)

        @mcp.tool()
        def get_conversations(file_path: str, proto: str = "tcp") -> str:
            """识别并统计会话"""
            convs = conv_get(file_path, proto, config.tshark_path)
            return json.dumps([c.model_dump() for c in convs], indent=2)

    def register_security_tools(self) -> None:
        """注册安全工具"""
        mcp = self.mcp

        @mcp.tool()
        async def check_ip_threats(ip: str) -> str:
            """单 IP 威胁情报查询"""
            engine = get_engine()
            data = await engine.check_ip(ip)
            return json.dumps(data, indent=2, ensure_ascii=False)

        @mcp.tool()
        async def check_threats(file_path: str) -> str:
            """[离线] 批量威胁扫描 PCAP 文件"""
            res = offline_analyze_pcap(file_path, "", 1000, config.tshark_path)
            if res.status != "success":
                return json.dumps({"status": "error", "message": res.error_message})

            ips = set()
            for pkt in res.packets:
                if pkt.five_tuple:
                    if pkt.five_tuple.src_ip: ips.add(pkt.five_tuple.src_ip)
                    if pkt.five_tuple.dst_ip: ips.add(pkt.five_tuple.dst_ip)

            # 过滤公网IP
            target_ips = []
            for ip in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not (ip_obj.is_private or ip_obj.is_loopback):
                        target_ips.append(str(ip_obj))
                except ValueError: pass

            target_ips = target_ips[:50] # 限制数量
            if not target_ips:
                return json.dumps({"status": "success", "message": "无公网IP", "data": {}})

            engine = get_engine()
            tasks = [engine.check_ip(ip) for ip in target_ips]
            threat_data = await asyncio.gather(*tasks)
            results = dict(zip(target_ips, threat_data))
            return json.dumps(results, indent=2, ensure_ascii=False)

        @mcp.tool()
        def extract_credentials(file_path: str, protocol: str = "all", limit: int = 5000) -> str:
            """提取凭证"""
            res = offline_analyze_pcap(file_path, "", limit, config.tshark_path)
            if res.status != "success":
                return json.dumps({"status": "error", "message": res.error_message})

            creds = extract_credentials_from_packets(res.packets, protocol)
            return json.dumps([c.model_dump() for c in creds], indent=2)


def register_tools(wireshark: "WiresharkMCP", mcp: FastMCP) -> None:
    """注册所有 MCP 工具的便捷函数"""
    registry = MCPToolRegistry(wireshark, mcp)
    registry.register_all()
