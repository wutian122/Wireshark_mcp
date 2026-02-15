"""
子进程管理模块

功能说明:
    封装 subprocess 调用，提供统一的 TShark 执行接口，
    包含错误处理、超时控制与日志记录。
"""
import subprocess
import logging
import asyncio
from typing import List, Tuple, Optional
from utils.errors import TSharkExecutionError

logger = logging.getLogger(__name__)

def run_tshark(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """
    运行 tshark 子进程（同步阻塞模式）

    功能: 执行传入命令并返回状态码与输出，支持超时控制。

    参数:
        cmd: 命令及参数列表
        timeout: 超时时间（秒），默认为 None

    返回:
        (returncode, stdout, stderr)

    异常:
        subprocess.TimeoutExpired: 执行超时
        Exception: 其他执行错误
    """
    try:
        logger.debug(f"执行命令: {' '.join(cmd)}")
        # Windows 平台避免弹出 CMD 窗口
        startupinfo = None
        if hasattr(subprocess, 'STARTUPINFO'):
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            startupinfo=startupinfo,
            encoding='utf-8',
            errors='replace'
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        logger.error(f"命令执行超时: {' '.join(cmd)}")
        raise
    except Exception as e:
        logger.error(f"命令执行异常: {e}")
        raise

async def run_tshark_async(cmd: List[str]) -> Tuple[int, str, str]:
    """
    运行 tshark 子进程（异步模式）

    功能: 异步执行命令，避免阻塞事件循环

    参数:
        cmd: 命令及参数列表

    返回:
        (returncode, stdout, stderr)
    """
    logger.debug(f"异步执行命令: {' '.join(cmd)}")
    # Windows 平台避免弹出窗口逻辑需在 asyncio 中特殊处理，此处简化
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await proc.communicate()

    return (
        proc.returncode or 0,
        stdout.decode('utf-8', errors='replace') if stdout else "",
        stderr.decode('utf-8', errors='replace') if stderr else ""
    )
