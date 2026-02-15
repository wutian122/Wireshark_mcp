import re
from typing import List
from utils.subproc import run_tshark
from schemas.conversation import ConversationSchema


def get_conversations(pcap_path: str, proto: str, tshark_path: str) -> List[ConversationSchema]:
    """识别 TCP/UDP 会话

    功能: 调用 tshark 会话统计并解析为结构化对象
    参数: pcap_path: 文件路径; proto: tcp/udp; tshark_path: 可执行路径
    返回: ConversationSchema 列表
    """
    z_arg = f"conv,{proto}" if proto in ("tcp", "udp") else "conv,tcp"
    code, out, err = run_tshark([tshark_path, "-r", pcap_path, "-q", "-z", z_arg])
    if code != 0:
        return []

    lines = out.splitlines()
    convs: List[ConversationSchema] = []
    pattern = re.compile(r"^(?P<src>[^\s:]+):(\d+)\s+(?P<dst>[^\s:]+):(\d+)\s+(?P<packets>\d+)\s+(?P<bytes>\d+)")
    for ln in lines:
        m = pattern.search(ln)
        if not m:
            continue
        parts = ln.split()
        src_port = int(parts[0].split(":")[1])
        dst_port = int(parts[1].split(":")[1])
        convs.append(ConversationSchema(
            proto=proto,
            src=m.group("src"),
            sport=src_port,
            dst=m.group("dst"),
            dport=dst_port,
            packets=int(m.group("packets")),
            bytes=int(m.group("bytes")),
        ))
    return convs

