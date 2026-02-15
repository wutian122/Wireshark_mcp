#!/usr/bin/env python3
"""
Wireshark MCP 服务器
基于 Model Context Protocol 的网络流量分析服务

功能说明:
    - 实时抓包与离线 PCAP 分析
    - 多协议深度解码
    - 威胁情报检测
    - 凭证提取分析
"""
import argparse
import logging
import os
import signal
import sys
from typing import Dict, List, Optional

# 将项目根目录添加到 Python 路径
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import uvicorn
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from mcp.server.fastmcp import FastMCP

from wireshark_mcp.tools import register_tools
from wireshark_mcp.config import config
from wireshark_mcp.logging_config import setup_logging, get_logger
from wireshark_mcp.handlers import homepage, get_system_info, print_banner
import utils.tshark_info as tshark_info
from utils.subproc import run_tshark
from utils.formatting import format_json_output
from datetime import datetime
import json

# 配置日志
logger = get_logger(__name__)


class WiresharkMCP:
    """
    Wireshark MCP 服务器核心类

    功能: 管理 TShark 路径验证和一部分遗留的业务逻辑
    """
    def __init__(self, tshark_path: str = None):
        """
        初始化 Wireshark MCP 服务器

        Args:
            tshark_path: tshark 可执行文件的路径 (如果未提供，尝试从配置获取)
        """
        self.tshark_path = tshark_path or config.tshark_path
        self._verify_tshark()
        self.running = True

    def _verify_tshark(self) -> None:
        """验证 tshark 是否可用及版本是否满足要求"""
        if not tshark_info.verify_tshark(self.tshark_path):
            raise RuntimeError(f"TShark 验证失败: {self.tshark_path}")

    def stop(self) -> None:
        """停止服务器"""
        self.running = False

    # --- 遗留方法 (保留以兼容 registry.py 中未迁移的工具) ---
    # TODO: 将以下方法迁移到 capture/ 或 analysis/ 模块中

    def _run_tshark_command(self, cmd: List[str], max_packets: int = 5000) -> str:
        """
        运行 tshark 命令并处理输出 (Legacy helper)
        """
        try:
            # 确保 max_packets 至少为 1
            if "-c" in cmd:
                try:
                    c_index = cmd.index("-c")
                    if c_index + 1 < len(cmd):
                        packet_count = max(1, int(cmd[c_index + 1]))
                        cmd[c_index + 1] = str(packet_count)
                except ValueError:
                    pass

            code, stdout, stderr = run_tshark(cmd)

            if code != 0:
                error_msg = f"tshark 命令执行失败: {stderr}"
                logger.error(error_msg)
                return json.dumps({
                    "error": error_msg,
                    "command": " ".join(cmd),
                    "建议": "请检查文件路径是否正确，以及是否有读取权限"
                }, ensure_ascii=False, indent=2)

            return format_json_output(stdout, max_packets, tshark_info.get_tshark_version(self.tshark_path))

        except Exception as e:
            logger.error(f"执行异常: {e}")
            return json.dumps({"error": str(e)}, ensure_ascii=False)

    def extract_fields(self, file_path: str, fields: List[str], filter: str = "", max_packets: int = 5000) -> str:
        """提取特定字段信息"""
        if not os.path.exists(file_path):
            return json.dumps({"error": f"找不到文件: {file_path}"}, ensure_ascii=False)

        cmd = [self.tshark_path, "-r", file_path, "-T", "fields"]
        for field in fields:
            cmd.extend(["-e", field])
        if filter:
            cmd.extend(["-Y", filter])
        if max_packets > 0:
            cmd.extend(["-c", str(max_packets)])

        return self._run_tshark_command(cmd, max_packets)

    def analyze_protocols(self, file_path: str, protocol: str = "", max_packets: int = 100) -> str:
        """分析特定协议的数据包"""
        if not os.path.exists(file_path):
            return json.dumps({"error": f"找不到文件: {file_path}"}, ensure_ascii=False)

        cmd = [self.tshark_path, "-r", file_path, "-T", "json", "-c", str(max_packets)]
        if protocol:
            cmd.extend(["-Y", protocol.lower()])

        return self._run_tshark_command(cmd, max_packets)

    def analyze_errors(self, file_path: str, error_type: str = "all", max_packets: int = 5000) -> str:
        """分析数据包中的错误"""
        if not os.path.exists(file_path):
            return json.dumps({"error": f"找不到文件: {file_path}"}, ensure_ascii=False)

        filters = {
            "all": "(_ws.malformed) or (tcp.analysis.flags) or (tcp.analysis.retransmission) or (tcp.analysis.duplicate_ack) or (tcp.analysis.lost_segment)",
            "malformed": "_ws.malformed",
            "tcp": "tcp.analysis.flags",
            "retransmission": "tcp.analysis.retransmission",
            "duplicate_ack": "tcp.analysis.duplicate_ack",
            "lost_segment": "tcp.analysis.lost_segment"
        }
        filter_expr = filters.get(error_type, filters["all"])

        cmd = [self.tshark_path, "-r", file_path, "-Y", filter_expr, "-T", "json", "-c", str(max_packets)]
        return self._run_tshark_command(cmd, max_packets)

    def get_packet_statistics(self, file_path: str, filter: str = "") -> str:
        """获取数据包统计信息"""
        cmd = [
            self.tshark_path, "-r", file_path, "-q",
            "-z", "io,stat,1",
            "-z", "conv,ip",
            "-z", "endpoints,ip"
        ]
        if filter:
            cmd.extend(["-Y", filter])
        return self._run_tshark_command(cmd)


def create_mcp_server(wireshark: WiresharkMCP) -> FastMCP:
    """创建 MCP 服务器实例"""
    mcp = FastMCP("Wireshark MCP")
    create_mcp_server.instance = mcp
    create_mcp_server.wireshark = wireshark
    register_tools(wireshark, mcp)
    return mcp


# 全局变量存储服务器实例
server_instance = None


def cleanup() -> None:
    """清理资源"""
    try:
        if hasattr(create_mcp_server, 'wireshark'):
            create_mcp_server.wireshark.stop()
        if hasattr(create_mcp_server, 'instance'):
            create_mcp_server.instance.shutdown()
    except Exception as e:
        logger.debug(f"清理资源时发生错误: {e}")


def handle_exit(signum, frame) -> None:
    """处理退出信号"""
    global server_instance
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)

    try:
        logger.info("正在关闭服务器...")
        cleanup()
        if server_instance:
            server_instance.should_exit = True
    except Exception as e:
        logger.debug(f"退出时发生错误: {e}")
    finally:
        os._exit(0)


def main() -> None:
    global server_instance

    parser = argparse.ArgumentParser(description="Wireshark MCP 服务器")
    parser.add_argument("--tshark-path", default=None, help="tshark 可执行文件路径")
    parser.add_argument("--host", default=None, help="服务器主机地址")
    parser.add_argument("--port", type=int, default=None, help="服务器端口")
    parser.add_argument("--transport", default="sse", choices=["sse", "stdio"], help="通信传输模式 (sse/stdio)")
    args = parser.parse_args()

    # 应用命令行参数到配置
    if args.host:
        config.data["server"]["host"] = args.host
    if args.port:
        config.data["server"]["port"] = args.port
    if args.tshark_path:
        config.data["wireshark"]["tshark_path"] = args.tshark_path

    # 获取系统信息并打印横幅
    system_info = get_system_info()
    if args.transport != "stdio":
        print_banner(system_info)

    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    try:
        wireshark = WiresharkMCP(config.tshark_path)
        mcp = create_mcp_server(wireshark)

        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            middleware = [
                Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
            ]
            routes = [
                Route("/status", homepage),
                Mount("/", app=mcp.sse_app())
            ]
            app = Starlette(routes=routes, middleware=middleware)

            host = config.data["server"]["host"]
            port = config.data["server"]["port"]

            logger.info(f"服务器地址: http://{host}:{port}")
            logger.info(f"状态页面: http://{host}:{port}/status")
            logger.info(f"SSE 端点: http://{host}:{port}/")

            uvicorn_config = uvicorn.Config(app, host=host, port=port, log_level="info")
            server_instance = uvicorn.Server(uvicorn_config)
            server_instance.run()

    except Exception as e:
        logger.error(f"服务器启动失败: {e}")
        cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()
