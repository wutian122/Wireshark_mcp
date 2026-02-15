"""
离线分析模块

功能说明:
    提供离线 PCAP 文件分析功能，调用 TShark 进行解析，
    并返回标准化数据模型。
"""
from typing import List
import os
from utils.subproc import run_tshark
from utils.formatting import build_capture_result
from schemas.packet import CaptureResultSchema, CaptureMetadata
from datetime import datetime
import json

def analyze_pcap(
    file_path: str,
    display_filter: str,
    limit: int,
    tshark_path: str,
    ssl_keylog_file: str = "",
    enable_reassembly: bool = True
) -> CaptureResultSchema:
    """
    离线 PCAP 分析

    功能: 解析本地 PCAP 并输出含负载的标准化数据模型
    参数:
        file_path: PCAP 文件路径
        display_filter: 显示过滤器 (Wireshark 语法)
        limit: 最大返回包数
        tshark_path: TShark 可执行文件路径
        ssl_keylog_file: SSL 解密密钥文件路径
        enable_reassembly: 是否启用 TCP 重组
    返回: CaptureResultSchema
    """
    version = _get_tshark_version(tshark_path)

    if not os.path.exists(file_path):
        return CaptureResultSchema(
            status="error",
            error_message=f"找不到文件: {file_path}",
            metadata=CaptureMetadata(
                timestamp=datetime.now().isoformat(),
                tshark_version=version,
                command=""
            )
        )

    cmd: List[str] = [
        tshark_path, "-r", file_path,
        "-T", "json", "-x", "-c", str(max(1, limit))
    ]

    if display_filter:
        cmd.extend(["-Y", display_filter])

    if enable_reassembly:
        cmd.extend(["-o", "tcp.desegment_tcp_streams:TRUE"])

    if ssl_keylog_file:
        cmd.extend(["-o", f"tls.keylog_file:{ssl_keylog_file}"])

    code, out, err = run_tshark(cmd, timeout=60) # 设置合理的超时时间

    if code != 0:
        return CaptureResultSchema(
            status="error",
            error_message=err or "TShark 执行失败",
            metadata=CaptureMetadata(
                timestamp=datetime.now().isoformat(),
                tshark_version=version,
                command=" ".join(cmd)
            )
        )

    return build_capture_result(out, limit, version, " ".join(cmd))

def _get_tshark_version(tshark_path: str) -> str:
    """获取 TShark 版本"""
    try:
        code, out, _ = run_tshark([tshark_path, "-v"], timeout=5)
        return out.split("\n")[0].strip() if code == 0 and out else "unknown"
    except Exception:
        return "unknown"
