"""
handlers 模块初始化

功能说明:
    HTTP 路由处理器模块，提供 Web 服务相关的请求处理。
"""
from .http_handlers import (
    homepage,
    root_redirect,
    get_system_info,
    print_banner,
    load_template
)

__all__ = [
    "homepage",
    "root_redirect", 
    "get_system_info",
    "print_banner",
    "load_template"
]
