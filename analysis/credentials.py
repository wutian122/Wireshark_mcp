from typing import List, Dict, Any
from schemas.credentials import CredentialSchema


def extract_credentials_from_packets(packets: List[Dict[str, Any]], protocol: str) -> List[CredentialSchema]:
    """从包中提取凭证

    功能: 支持 HTTP Basic、FTP、Telnet 等基础协议的凭证提取
    参数: packets: tshark json 包; protocol: 协议名
    返回: CredentialSchema 列表
    """
    creds: List[CredentialSchema] = []
    proto = protocol.lower()

    for idx, pkt in enumerate(packets):
        layers = pkt.get("_source", {}).get("layers", {})
        
        # HTTP
        if proto in ("http", "all") and "http" in layers:
            auth = layers["http"].get("http.authorization")
            if auth:
                val = auth[0] if isinstance(auth, list) else auth
                if isinstance(val, str) and val.lower().startswith("basic "):
                    creds.append(CredentialSchema(protocol="http", evidence_packet_ids=[idx]))
                    
        # FTP
        if proto in ("ftp", "all") and "ftp" in layers:
            user = layers["ftp"].get("ftp.request.arg") if "ftp.request.command" in layers and layers["ftp.request.command"] == "USER" else None
            pw = layers["ftp"].get("ftp.request.arg") if "ftp.request.command" in layers and layers["ftp.request.command"] == "PASS" else None
            
            # 由于 tshark 输出是以包为单位，这里简化处理，只提取看到的字段
            # 实际场景可能需要流重组来匹配 USER/PASS 对，这里仅提取单包信息
            if layers.get("ftp.request.command") == "USER":
                val = layers.get("ftp.request.arg")
                u = val[0] if isinstance(val, list) else val
                creds.append(CredentialSchema(protocol="ftp", username=u, evidence_packet_ids=[idx]))
            if layers.get("ftp.request.command") == "PASS":
                val = layers.get("ftp.request.arg")
                p = val[0] if isinstance(val, list) else val
                creds.append(CredentialSchema(protocol="ftp", password=p, evidence_packet_ids=[idx]))

            # 旧逻辑兼容 (针对不同 tshark 版本字段差异)
            if not user and not pw:
                user = layers["ftp"].get("ftp.req.user")
                pw = layers["ftp"].get("ftp.req.pass")
                if user or pw:
                    u = user[0] if isinstance(user, list) else user
                    p = pw[0] if isinstance(pw, list) else pw
                    creds.append(CredentialSchema(protocol="ftp", username=u, password=p, evidence_packet_ids=[idx]))

        # Telnet
        if proto in ("telnet", "all") and "telnet" in layers:
            data = layers["telnet"].get("telnet.data")
            if data:
                creds.append(CredentialSchema(protocol="telnet", evidence_packet_ids=[idx]))

        # SMTP
        if proto in ("smtp", "all") and "smtp" in layers:
            # 简单的 AUTH PLAIN/LOGIN提取 (Base64)
            if "smtp.auth.username" in layers:
                val = layers["smtp.auth.username"]
                u = val[0] if isinstance(val, list) else val
                creds.append(CredentialSchema(protocol="smtp", username=u, evidence_packet_ids=[idx]))
            if "smtp.auth.password" in layers:
                val = layers["smtp.auth.password"]
                p = val[0] if isinstance(val, list) else val
                creds.append(CredentialSchema(protocol="smtp", password=p, evidence_packet_ids=[idx]))

        # POP3
        if proto in ("pop", "all") and "pop" in layers:
            req = layers["pop"].get("pop.request")
            if req:
                cmd = req.split()[0].upper() if isinstance(req, str) else ""
                arg = layers["pop"].get("pop.request.parameter", "")
                arg = arg[0] if isinstance(arg, list) else arg
                
                if cmd == "USER":
                    creds.append(CredentialSchema(protocol="pop3", username=arg, evidence_packet_ids=[idx]))
                elif cmd == "PASS":
                     creds.append(CredentialSchema(protocol="pop3", password=arg, evidence_packet_ids=[idx]))
                     
        # IMAP
        if proto in ("imap", "all") and "imap" in layers:
             req = layers["imap"].get("imap.request")
             if req: # 包含 LOGIN 命令
                 # imap.request.command 不是标准字段，imap解析比较复杂
                 # 尝试查找 simple_login 字段
                 pass

        # LDAP
        if proto in ("ldap", "all") and "ldap" in layers:
            bind_dn = layers["ldap"].get("ldap.bind.dn") # Simple Bind
            simple_pw = layers["ldap"].get("ldap.simple_auth")
            if bind_dn or simple_pw:
                 u = bind_dn[0] if isinstance(bind_dn, list) and bind_dn else bind_dn
                 p = simple_pw[0] if isinstance(simple_pw, list) and simple_pw else simple_pw
                 creds.append(CredentialSchema(protocol="ldap", username=u, password=p, evidence_packet_ids=[idx]))

    return creds

