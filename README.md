# Wireshark MCP Server

这是一个基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 的 Wireshark 流量分析服务器。它将强大的 Wireshark/Tshark 网络分析能力暴露给 AI 助手（如 Claude），使其能够直接进行网络数据包的抓取、解析、统计和安全分析。

## 🌟 核心功能

*   **实时抓包与分析**：直接调用 Tshark 进行实时流量捕获，支持 BPF 和显示过滤器。
*   **离线 PCAP 分析**：读取并深度解析 `.pcap`/`.pcapng` 文件，支持 SSL/TLS 解密（需提供 Keylog）。
*   **深度协议解码**：利用 Wireshark 强大的解码引擎，支持数千种网络协议的解析。
*   **一键式自动化威胁扫描 (New)**：
    *   提供 `scan_network_threats` 复合工具，单次调用即可自动完成“接口选择 -> 抓包 -> 分析 -> 查杀 -> 报告”全流程。
    *   无需人工干预，自动识别最佳网络接口。
    *   生成结构化的 Markdown 安全评估报告。
*   **安全威胁检测**：
    *   集成 **AbuseIPDB** 多源威胁情报。
    *   **多 API Key 智能轮换**：支持配置多个 API Key，自动轮换使用，大幅提升查询限额。
    *   三种轮换策略：智能（Smart）、轮询（Round Robin）、加权（Weighted）。
    *   自动速率限制检测与恢复，失败 Key 自动隔离与重试。
    *   多源情报聚合查询架构（支持扩展）。
    *   本地 LRU+TTL 缓存机制，减少 API 调用消耗。
    *   异步并发查询与增强的重试机制。
*   **统计与可视化数据**：提供协议分布、会话统计、端点统计、错误分析等宏观数据。
*   **凭证提取**：支持从 **HTTP, FTP, SMTP, POP3, IMAP, LDAP, Telnet** 流量中提取凭证。

## 📁 项目结构

```
Wireshark_mcp/
├── wireshark_mcp/
│   ├── threat_intel/       # 威胁情报核心模块
│   │   ├── core.py         # 聚合引擎与重试逻辑
│   │   ├── sources.py      # 情报源实现 (AbuseIPDB)
│   │   └── cache.py        # 本地 LRU+TTL 缓存
│   ├── tools/              # MCP 工具注册模块
│   ├── capture/            # 抓包功能 (实时/离线)
│   ├── analysis/           # 分析功能 (统计/会话/凭证)
│   ├── schemas/            # Pydantic 数据模型
│   ├── server.py           # 服务器入口
│   ├── config.py           # 配置管理 (Pydantic/YAML)
│   └── logging_config.py   # 日志配置
├── tests/                  # 测试组件
├── config.example.yaml     # 配置文件示例
├── requirements.txt        # 项目依赖
├── main.py                 # 程序入口
├── README.md               # 本文档
└── ...
```

## 🚀 快速开始

### 1. 安装 Wireshark / TShark（必需）

本项目依赖 **TShark**（Wireshark 的命令行版本）进行所有抓包和协议解析操作。

#### Windows 安装步骤

1.  **下载 Wireshark**: 访问 [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)，下载 Windows 安装包。
2.  **安装时勾选 TShark**: 运行安装程序，在组件选择页面确保勾选了 **TShark** 组件（默认已勾选）。
3.  **添加到系统 PATH**:
    *   安装完成后，打开"系统属性" → "高级" → "环境变量"。
    *   在"系统变量"中找到 `Path`，点击"编辑"。
    *   添加 Wireshark 安装目录，通常为：`C:\Program Files\Wireshark`。
    *   保存并重启终端。

4.  **验证安装**: 打开 PowerShell，运行以下命令：
    ```powershell
    tshark --version
    ```
    如果看到类似 `TShark (Wireshark) 4.x.x` 的版本信息，说明安装成功。

#### 手动指定 TShark 路径（可选）

如果您不想修改系统 PATH，可以在 `config.yaml` 中直接指定 TShark 的完整路径：

```yaml
wireshark:
  tshark_path: "C:\\Program Files\\Wireshark\\tshark.exe"
```

### 2. 安装 Python 依赖

确保您已安装 Python 3.10+，然后运行：

```bash
cd YOUR_PROJECT_PATH
pip install -r requirements.txt
```

### 3. 创建配置文件

复制示例配置文件：
```bash
copy config.example.yaml config.yaml
```

根据需要编辑 `config.yaml`，填入您的威胁情报 API Key（可选）。

### 4. 配置 Claude Desktop

编辑 Claude Desktop 配置文件：
*   **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
*   **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

添加以下内容：

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": [
        "YOUR_PROJECT_PATH/main.py",
        "--transport",
        "stdio"
      ]
    }
  }
}
```
> **注意**: 请将 `YOUR_PROJECT_PATH` 替换为实际项目路径（例如 `C:\Users\YourName\Wireshark_mcp` 或 `/Users/YourName/Wireshark_mcp`）。

### 5. 配置
1.  **环境变量** (推荐，符合 MCP 标准)
2.  **配置文件** (`config.json`)
3.  **默认值**

#### 方法 A: MCP 客户端配置 (推荐)

在 Claude Desktop 配置文件中直接注入环境变量。

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": [
        "YOUR_PROJECT_PATH/main.py",
        "--transport", "stdio"
      ],
      "env": {
        "THREATBOOK_API_KEY": "YOUR_API_KEY_HERE",
        "WIRESHARK_DEFAULT_INTERFACE": "1",
        "WIRESHARK_TSHARK_PATH": "tshark"
      }
    }
  }
}
```

**配置字段说明：**
*   **`wireshark`**: 服务唯一标识符，您可以自定义此名称。
*   **`command`**: 启动服务的可执行程序命令（如 `python` 或 `uv`）。
*   **`args`**: 传递给启动命令的参数列表。
*   **脚本路径**: `main.py` 的绝对路径（请根据实际部署位置修改）。
*   **`--transport stdio`**: 指定使用标准输入/输出作为通信信道（**必须保留**）。
*   **`env`**: 注入到服务进程的环境变量（优先级最高）。
*   **`THREATBOOK_API_KEY`**: [微步在线](https://x.threatbook.com/) API Key，用于威胁情报查询（单个Key）。
*   **`WIRESHARK_DEFAULT_INTERFACE`**: 默认抓包网卡索引（建议使用数字索引以避免乱码）。
*   **`WIRESHARK_TSHARK_PATH`**: `tshark` 可执行文件的路径或命令（默认 "tshark"）。

##### 🆕 多 API Key 配置（提升使用量）

如果您有多个 API Key，可以通过配置文件实现智能轮换，大幅提升查询限额：

**步骤 1**：创建 `config.json` 文件（与 `main.py` 同目录）

```json
{
  "threat_intel": {
    "threatbook_api_keys": [
      {
        "key": "YOUR_FIRST_API_KEY",
        "name": "primary",
        "enabled": true,
        "weight": 100
      },
      {
        "key": "YOUR_SECOND_API_KEY",
        "name": "secondary",
        "enabled": true,
        "weight": 80
      },
      {
        "key": "YOUR_THIRD_API_KEY",
        "name": "tertiary",
        "enabled": true,
        "weight": 60
      }
    ],
    "api_key_rotation": {
      "strategy": "smart",
      "failure_threshold": 3,
      "rate_limit_backoff": 3600,
      "health_check_interval": 300
    }
  },
  "wireshark": {
    "default_interface": "1",
    "min_version": "3.0.0",
    "tshark_path": "tshark"
  }
}
```

**配置说明：**
*   **`threatbook_api_keys`**: API Key 列表
    *   `key`: API Key 字符串
    *   `name`: Key 的名称（用于日志和统计）
    *   `enabled`: 是否启用该 Key
    *   `weight`: 权重值（用于加权轮换策略）
*   **`api_key_rotation`**: 轮换策略配置
    *   `strategy`: 轮换策略（`smart`/`round_robin`/`weighted`）
    *   `failure_threshold`: 连续失败次数阈值（超过则禁用）
    *   `rate_limit_backoff`: 速率限制后的退避时间（秒）
    *   `health_check_interval`: 健康检查间隔（秒）

**步骤 2**：更新 MCP 客户端配置（移除单个 API Key）

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": [
        "YOUR_PROJECT_PATH/main.py",
        "--transport", "stdio"
      ],
      "env": {
        "WIRESHARK_DEFAULT_INTERFACE": "1",
        "WIRESHARK_TSHARK_PATH": "tshark"
      }
    }
  }
}
```

## 🛠️ MCP 工具列表

### 1. 基础工具
*   **`verify_environment` (New)**
    *   功能：一键检查 TShark 环境、版本兼容性、API Key 状态及网络接口识别情况。
    *   用途：排查配置问题。

*   **`list_interfaces`**
    *   功能：列出所有可用的网络接口及其索引。
    *   特性：输出包含智能推荐的最佳接口。

*   **`get_protocols`**
    *   功能：获取 Wireshark 支持的所有协议列表。

### 2. 抓包工具
*   **`capture_live`**
    *   功能：简易实时抓包。
    *   参数：`interface` (可选, 默认自动选择最佳接口), `duration` (秒), `filter` (BPF过滤), `max_packets` (最大包数)。
    *   **特性**：若不指定接口，工具会自动识别流量最活跃的物理网卡。

*   **`capture_packets`** (高级)
    *   功能：高级实时抓包，支持 SSL Keylog 和 TLS 重组。
    *   参数：`interface` (可选, 默认自动选择), `duration`, `bpf_filter` (捕获前过滤), `display_filter` (捕获后过滤), `limit`, `ssl_keylog_file` (解密密钥文件路径), `enable_reassembly` (是否重组TCP流)。

### 3. 自动化与复合工具 (New)
*   **`scan_network_threats`**
    *   **功能**：一键式网络威胁扫描与评估。
    *   **流程**：自动选择接口 -> 抓取实时流量 -> 提取公网 IP -> 查询威胁情报 -> 生成 Markdown 报告。
    *   **参数**：
        *   `duration`: 扫描持续时间（秒，默认 30）。
        *   `max_packets`: 最大分析包数（默认 1000）。
    *   **用途**：AI Agent 可直接调用此工具进行“自主安全审计”，无需分步操作。

### 4. 分析工具
*   **`analyze_pcap`**
    *   功能：简易 PCAP 文件分析。
    *   参数：`file_path`, `filter`, `max_packets`.

*   **`analyze_pcap_full`** (高级)
    *   功能：高级 PCAP 分析，支持解密和重组。
    *   参数：`file_path`, `display_filter`, `limit`, `ssl_keylog_file`, `enable_reassembly`.

*   **`extract_fields`**
    *   功能：从 PCAP 文件中提取特定字段信息。
    *   参数：`file_path`, `fields` (列表), `filter`, `max_packets`.

*   **`analyze_protocols`**
    *   功能：分析特定协议的数据包分布与详情。
    *   参数：`file_path`, `protocol` (如 "http"), `max_packets`.

*   **`analyze_errors`**
    *   功能：分析数据包中的 TCP 错误（重传、乱序等）。
    *   参数：`file_path`, `error_type` (all/malformed/tcp/duplicate_ack/lost_segment).

### 5. 统计工具
*   **`get_packet_statistics`**
    *   功能：获取 PCAP 文件的基础统计信息 (IO, 时间, 大小)。
    *   参数：`file_path`, `filter`.

*   **`get_summary_stats`**
    *   功能：获取协议分层统计概览。
    *   参数：`file_path`, `display_filter`, `limit`.

*   **`get_conversations`**
    *   功能：识别并统计 TCP/UDP 会话列表。
    *   参数：`file_path`, `proto` (tcp/udp).

### 6. 安全与情报工具
*   **`check_ip_threats`**
    *   功能：查询单个 IP 的威胁情报（支持微步在线）。
    *   参数：`ip`.
    *   特性：自动缓存结果，支持失败重试。

*   **`check_threats`**
    *   功能：批量扫描 PCAP 文件中的所有 IP，识别恶意主机。
    *   参数：`file_path`.
    *   特性：异步并发查询，快速生成报告。

*   **`extract_credentials`**
    *   功能：从流量中提取明文凭证（HTTP Basic, FTP, SMTP 等）。
    *   参数：`file_path`, `protocol`, `limit`.

## ⚠️ 已知问题与解决方案

1.  **接口名称乱码**：
    *   **现象**：在中文 Windows 环境下，接口描述可能包含乱码。
    *   **解决**：工具已内置处理逻辑，但强烈建议在配置或参数中**直接使用接口索引号**（如 "1", "9" 等），不要使用中文名称。

2.  **TLS 重组参数警告**：
    *   **说明**：旧版 `tls.desegment_tls_records` 参数已弃用。
    *   **解决**：新版代码已自动处理此参数，无需人工干预。

## ⚙️ 高级配置

项目支持通过 `config.yaml` 或 `config.json` 进行深度配置。详细配置项请参考 [config.example.yaml](config.example.yaml)。

主要配置项包括：
*   **threat_intel**: 配置 ThreatBook, VirusTotal, AbuseIPDB 的 API Key 及轮换策略。
*   **wireshark**: 设置默认网卡接口、TShark 路径。
*   **server**: HTTP 服务器监听地址（仅 SSE 模式）。
