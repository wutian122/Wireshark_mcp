"""
Wireshark MCP 异常定义模块

功能说明:
    定义项目中使用的统一异常体系，便于错误捕获与处理。
"""

class WiresharkError(Exception):
    """Wireshark MCP 项目基类异常"""
    def __init__(self, message: str, original_error: Exception = None):
        super().__init__(message)
        self.original_error = original_error

class TSharkNotFoundError(WiresharkError):
    """找不到 TShark 可执行文件时抛出"""
    pass

class TSharkExecutionError(WiresharkError):
    """TShark 执行失败（非零退出码）时抛出"""
    def __init__(self, message: str, command: list, stderr: str):
        super().__init__(message)
        self.command = command
        self.stderr = stderr

class CaptureError(WiresharkError):
    """抓包过程中发生的错误"""
    pass

class AnalysisError(WiresharkError):
    """分析 PCAP 文件或数据时发生的错误"""
    pass
