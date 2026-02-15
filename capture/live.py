"""
实时抓包模块

功能说明:
    提供实时抓包功能，调用 TShark 进行流量捕获，
    并返回标准化数据模型。
"""
from typing import List
from utils.subproc import run_tshark
from utils.formatting import build_capture_result
from schemas.packet import CaptureResultSchema, CaptureMetadata
from datetime import datetime
import json

def capture_packets(
    interface: str,
    duration: int,
    bpf_filter: str,
    display_filter: str,
    limit: int,
    tshark_path: str,
    ssl_keylog_file: str = "",
    enable_reassembly: bool = True
) -> CaptureResultSchema:
    """
    实时抓包

    功能: 在指定接口上进行实时抓包，返回标准化数据模型
    参数:
        interface: 接口名称
        duration: 抓包持续时间(秒)
        bpf_filter: 捕获过滤器 (BPF 语法)
        display_filter: 显示过滤器 (Wireshark 语法)
        limit: 最大返回包数
        tshark_path: TShark 可执行文件路径
        ssl_keylog_file: SSL 解密密钥文件路径
        enable_reassembly: 是否启用 TCP 重组
    返回: CaptureResultSchema
    """
    cmd: List[str] = [
        tshark_path, "-i", interface, "-a", f"duration:{duration}",
        "-T", "json", "-x", "-c", str(max(1, limit))
    ]

    if bpf_filter:
        cmd.extend(["-f", bpf_filter])

    if display_filter:
        cmd.extend(["-Y", display_filter])

    if enable_reassembly:
        cmd.extend(["-o", "tcp.desegment_tcp_streams:TRUE"])

    if ssl_keylog_file:
        cmd.extend(["-o", f"tls.keylog_file:{ssl_keylog_file}"])

    # 增加超时时间以防止僵尸进程，比 duration 多 5 秒余量
    code, out, err = run_tshark(cmd, timeout=duration + 5)
    version = _get_tshark_version(tshark_path)

    if code != 0:
        # 构建错误结果
        return CaptureResultSchema(
            status="error",
            error_message=err or "TShark 执行失败",
            metadata=CaptureMetadata(
                timestamp=datetime.now().isoformat(),
                tshark_version=version,
                command=" ".join(cmd),
                duration=float(duration)
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
