"""
统一日志配置模块

功能说明:
    提供项目统一的日志配置和格式化支持，支持彩色输出和多种日志级别。

使用方式:
    from wireshark_mcp.logging_config import setup_logging, get_logger
    
    # 在应用启动时初始化
    setup_logging(level="INFO")
    
    # 在各模块中获取 logger
    logger = get_logger(__name__)
"""
import logging
import sys
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """
    彩色日志格式化器
    
    功能: 为不同日志级别设置不同颜色，提升日志可读性
    
    颜色映射:
        - DEBUG: 灰色
        - INFO: 蓝色
        - WARNING: 黄色
        - ERROR: 红色
        - CRITICAL: 粗体红色
    """
    
    # ANSI 颜色代码
    GREY = "\x1b[38;21m"
    BLUE = "\x1b[38;5;39m"
    YELLOW = "\x1b[38;5;226m"
    RED = "\x1b[38;5;196m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"
    
    # 日志格式
    LOG_FORMAT = "%(asctime)s %(levelname)s: %(message)s"
    DATE_FORMAT = "%H:%M:%S"

    def __init__(self, use_colors: bool = True):
        """
        初始化格式化器
        
        Args:
            use_colors: 是否启用颜色输出（Windows 终端可能不支持）
        """
        super().__init__()
        self.use_colors = use_colors
        
        self.FORMATS = {
            logging.DEBUG: self.GREY + self.LOG_FORMAT + self.RESET,
            logging.INFO: self.BLUE + self.LOG_FORMAT + self.RESET,
            logging.WARNING: self.YELLOW + self.LOG_FORMAT + self.RESET,
            logging.ERROR: self.RED + self.LOG_FORMAT + self.RESET,
            logging.CRITICAL: self.BOLD_RED + self.LOG_FORMAT + self.RESET
        }
        
        self.PLAIN_FORMAT = self.LOG_FORMAT

    def format(self, record: logging.LogRecord) -> str:
        """
        格式化日志记录
        
        Args:
            record: 日志记录对象
            
        Returns:
            格式化后的日志字符串
        """
        if self.use_colors:
            log_fmt = self.FORMATS.get(record.levelno, self.PLAIN_FORMAT)
        else:
            log_fmt = self.PLAIN_FORMAT
            
        formatter = logging.Formatter(log_fmt, datefmt=self.DATE_FORMAT)
        return formatter.format(record)


def setup_logging(
    level: str = "INFO",
    use_colors: bool = True,
    log_file: Optional[str] = None
) -> None:
    """
    配置项目统一日志系统
    
    功能: 设置根日志器配置，包括控制台输出和可选的文件输出
    
    Args:
        level: 日志级别字符串 ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
        use_colors: 是否在控制台启用彩色输出
        log_file: 可选的日志文件路径，设置后同时输出到文件
        
    Example:
        >>> setup_logging(level="DEBUG", use_colors=True)
        >>> setup_logging(level="INFO", log_file="/var/log/wireshark_mcp.log")
    """
    # 解析日志级别
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # 获取根日志器
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # 清除现有处理器
    root_logger.handlers.clear()
    
    # 控制台处理器
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(ColoredFormatter(use_colors=use_colors))
    root_logger.addHandler(console_handler)
    
    # 文件处理器（可选）
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        root_logger.addHandler(file_handler)
    
    # 降低第三方库日志级别
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    获取指定名称的日志器
    
    功能: 统一的日志器获取接口，便于追踪日志来源
    
    Args:
        name: 日志器名称，通常使用 __name__
        
    Returns:
        logging.Logger: 配置好的日志器实例
        
    Example:
        >>> logger = get_logger(__name__)
        >>> logger.info("操作成功")
    """
    return logging.getLogger(name)


def silence_library_loggers() -> None:
    """
    静默第三方库的日志输出
    
    功能: 将常见第三方库的日志级别设置为 WARNING，减少日志噪音
    """
    libraries = [
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "httpx",
        "httpcore",
        "asyncio"
    ]
    
    for lib in libraries:
        logging.getLogger(lib).setLevel(logging.WARNING)
