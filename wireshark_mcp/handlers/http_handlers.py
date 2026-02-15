"""
HTTP 路由处理器模块

功能说明:
    处理 HTTP 路由相关的请求处理函数，包括状态页面和重定向逻辑。
    从 server.py 分离的 HTTP 处理逻辑。
"""
import os
import platform
import subprocess
from pathlib import Path
from typing import Dict

from starlette.responses import HTMLResponse, RedirectResponse
from starlette.requests import Request


# 模板目录路径
TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def load_template(template_name: str) -> str:
    """
    加载 HTML 模板文件
    
    功能: 从 templates 目录读取指定的 HTML 模板
    
    Args:
        template_name: 模板文件名（如 "status.html"）
        
    Returns:
        HTML 模板内容字符串
        
    Raises:
        FileNotFoundError: 模板文件不存在时抛出
    """
    template_path = TEMPLATE_DIR / template_name
    
    if not template_path.exists():
        raise FileNotFoundError(f"模板文件不存在: {template_path}")
        
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()


def homepage(request: Request) -> HTMLResponse:
    """
    根路由处理器 - 服务状态页面
    
    功能: 返回服务器状态页面，展示可用工具列表和系统信息
    
    Args:
        request: Starlette 请求对象
        
    Returns:
        HTMLResponse: 包含状态页面的 HTML 响应
    """
    try:
        html_content = load_template("status.html")
    except FileNotFoundError:
        # 降级处理：返回简单的状态页面
        html_content = """
        <!DOCTYPE html>
        <html>
        <head><title>Wireshark MCP</title></head>
        <body>
            <h1>Wireshark MCP 服务器</h1>
            <p style="color: green;">● 服务器运行正常</p>
            <p>模板文件加载失败，请检查 templates/status.html</p>
        </body>
        </html>
        """
    
    return HTMLResponse(html_content)


async def root_redirect(request: Request) -> RedirectResponse:
    """
    根路径重定向处理器
    
    功能: 将根路径 "/" 重定向到状态页面 "/status"
    
    Args:
        request: Starlette 请求对象
        
    Returns:
        RedirectResponse: 重定向到 /status 的响应
    """
    return RedirectResponse(url="/status")


def get_system_info() -> Dict[str, str]:
    """
    获取系统运行环境信息
    
    功能: 收集 Python 版本、操作系统和 TShark 版本信息
    
    Returns:
        包含系统信息的字典:
            - python_version: Python 版本号
            - os_platform: 操作系统平台信息
            - tshark_version: TShark 版本号
    """
    info = {
        "python_version": platform.python_version(),
        "os_platform": platform.platform(),
        "tshark_version": "未知"
    }
    
    try:
        # 获取 tshark 版本
        proc = subprocess.run(
            ["tshark", "-v"],
            capture_output=True,
            text=True,
            check=True
        )
        info["tshark_version"] = proc.stdout.split("\n")[0].strip()
    except Exception:
        pass
        
    return info


def print_banner(system_info: Dict[str, str]) -> None:
    """
    打印服务器启动横幅
    
    功能: 在服务器启动时打印格式化的系统信息横幅
    
    Args:
        system_info: 系统信息字典，来自 get_system_info()
    """
    banner = f"""
╔══════════════════════════════════════════════════════════════════╗
║                    Wireshark MCP 服务器启动                      ║
╠══════════════════════════════════════════════════════════════════╣
║ 系统信息:                                                        ║
║ • Python: {system_info['python_version']:<52} ║
║ • 操作系统: {system_info['os_platform']:<50} ║
║ • TShark: {system_info['tshark_version']:<52} ║
╚══════════════════════════════════════════════════════════════════╝
"""
    print(banner)
