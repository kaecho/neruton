# Neruton

> 轻量级自托管内网穿透工具、泛域名反向代理与免绑域名 Web 预览面板（受 `cloudflared` 启发，纯 Rust + Next.js 构建）。  
> Lightweight, self-hosted intranet tunnel, wildcard subdomain reverse proxy, and zero-extra-domain web viewer inspired by `cloudflared`.

[中文文档](#中文文档) · [English Documentation](#english-documentation) · [Latest Releases](https://github.com/kaecho/neruton/releases/latest)

---

## 中文文档

### 核心特性（v0.4.0）

- **单连接穿透 443 端口（WSS + Yamux）**：客户端通过一条出站 WebSocket (`wss://`) 连接接入服务端，内部采用 **Yamux** 多路复用并发 HTTP/1.1 与 WebSocket 流量，天然穿越 NAT、企业防火墙以及 Cloudflare 代理。
- **默认隐蔽传输（RFC 8484 DoH + 真 TLS 1.3 ECH）**：非本地 `wss://` 连接默认启用基于 IP 端点的 **DNS-over-HTTPS**（零引导明文 DNS 泄露，自动跳过 `localhost` / `.local` / IP 字面量）与 **SNI 隐藏（`--sni-mode auto`）**——**Rust CLI、Python SDK 与 Node.js SDK 三端均原生实现真实加密 TLS 1.3 ECH（RFC 8446 + RFC 9180 HPKE + RFC 9849）**，自动通过 DoH `HTTPS` (Type 65) 记录获取 `ECHConfigList`（支持自动单次 `retry_configs` 重试），目标服务端未发布 ECH 记录时自动回退至 ClientHello TCP 分片，全程保持完整 TLS 1.3 证书校验。
- **泛域名路由（Wildcard Subdomain）**：支持自动生成随机 UUID v4 前缀（如 `https://<uuid>.moer.eu.org`），也支持通过 `--subdomain test-test` 绑定自定义子域名（如 `https://test-test.moer.eu.org`）。
- **免额外域名 Web 直览（`/preview/<prefix>` 与 `/t/<prefix>/`）**：无需为每个内网服务额外配置域名，可直接在 Web 控制台的 `/preview/<prefix>` 嵌入式浏览器中预览和调试隧道内容；服务端自动通过 `/t/<prefix>/` 路径代理转发、放松 iframe 限制并注入 `<base>` 标签。
- **Web 账户认证与多用户 RBAC 管理**：
  - 支持首次启动 Web 界面交互式初始化管理员账户（或通过环境变量自动初始化），密码使用纯 Rust **Argon2** 哈希存储，会话采用 HMAC-SHA256 签名 `HttpOnly` Cookie (`neruton_session`)。
  - 支持 `admin` 与 `user` 两种角色：管理员可在 `/users` 页面创建、禁用/启用、切换角色、重置密码或删除用户；普通用户仅可查看和管理归属自己的隧道、令牌与请求日志。
- **隧道令牌鉴权（默认开启，可实时开关）**：
  - 默认启用强制隧道令牌鉴权（`NERUTON_REQUIRE_AUTH=true`），用户在 `/tokens` 页面创建带前缀白名单（可选）的独立令牌（`ntk_...`），明文仅展示一次，服务端仅保存 SHA-256 哈希。
  - 禁用或撤销令牌会立即断开使用该令牌的在线隧道；管理员可在 `/settings` 页面随时在线切换「强制要求隧道 Token 鉴权」开关（支持开放模式与受控模式无缝切换），同时兼容可选的全局主令牌 `NERUTON_AUTH_TOKEN`。
- **保留前缀与用户配额管理**：内置保护前缀（`neruton`、`www`、`api`、`admin`、`_neruton` 及面板子域），管理员可在 `/settings` 中实时维护自定义保留前缀列表与单用户最大隧道配额（`max_tunnels_per_user`）。
- **零公网暴露端口部署与状态持久化**：服务端 Docker Compose 栈内置 `cloudflared`，所有入站流量经 Cloudflare Tunnel 进入内部 Docker 网络 `neruton-net`，宿主机无需开放任何端口；账户、令牌哈希、会话密钥与运行配置原子持久化至命名卷 `neruton-data`（挂载在 `/data/state.json`）。
- **Geist 风格实时控制台与流量审计**：基于 Vercel Geist 设计语言重构的 Next.js 管理控制台，提供概览（`/`）、令牌（`/tokens`）、实时 SSE 日志（`/logs`）、用户管理（`/users`）、系统与账户设置（`/settings`）以及全高嵌入式预览器（`/preview/<prefix>`）。
- **原生 Python 与 Node.js / TypeScript SDK**：除 Rust 二进制 CLI 外，另提供原生 Python（`pip install neruton`，基于 `cryptography>=42.0.0`，支持 Python 3.9–3.14 及 Colab / Kaggle）与纯 Node.js / TypeScript（`npm install neruton`，仅用内置 `node:crypto` + `node:tls`，零额外 npm 依赖，Node >= 18）实现，完整内置 Yamux v0 多路复用器、HTTP/1.1 / WebSocket 转发器与真 TLS 1.3 ECH，支持以库方式嵌入业务进程或作为独立 CLI 使用，并与 Rust CLI 共享 `~/.config/neruton/config.toml` 配置。

### 架构概览

```text
+-------------------+       WSS + Yamux (:443)       +------------------+
| Local Service     | <--- neruton CLI ------------> | Cloudflare Edge  |
| (localhost:3000)  |      (outbound + ntk_ token)   | *.moer.eu.org    |
+-------------------+                                | neruton.moer...  |
                                                     +--------+---------+
                                                              | Cloudflare Tunnel
                                                              | (zero host ports)
                                                     +--------v---------+
                                                     | cloudflared      |
                                                     +--------+---------+
                                                              | neruton-net
                                                     +--------v---------+     +------------------+
                                                     | neruton-server   +---->| neruton-data     |
                                                     | :8080 (Rust)     |     | (/data/state.json|
                                                     +---+----------+---+     +------------------+
                                    Wildcard / /t/*  |              | Panel UI /*
                                     (Yamux stream)  |              v
                                                     |     +----------------+
                                                     |     | neruton-web    |
                                                     |     | :3000 (NextJS) |
                                                     |     +----------------+
```

- **泛域名访问**：`Host: <prefix>.moer.eu.org` -> `neruton-server` 通过 Yamux 流直接代理到对应客户端本地服务。
- **面板与路径预览**：`Host: neruton.moer.eu.org`
  - `/_neruton/tunnel`：客户端 WebSocket + Yamux 控制与数据通道（支持 `Authorization: Bearer <token>` 或 `?token=...`）
  - `/_neruton/health` & `/_neruton/api/*`：健康检查、账户认证、令牌/用户/系统设置管理 API 与 SSE 实时事件流
  - `/t/<prefix>/...`：免额外域名路径代理（自动重写相对跳转与 `<base href="/t/<prefix>/">`）
  - `/preview/<prefix>`、`/login`、`/tokens`、`/logs`、`/users`、`/settings` & `/`：反向代理到 `neruton-web` Next.js 控制台

### 首次启动与账户初始化

部署并启动服务端后，访问控制台（例如 `https://neruton.moer.eu.org`）：

1. **交互式初始化（推荐，默认方式）**：保持 `.env` 中 `NERUTON_ADMIN_PASSWORD` 为空，首次打开 Web 面板会自动进入「初始化管理员账户」页面。创建管理员账号（密码至少 8 位）后，系统会自动签发一个名为 `Default CLI Token` 的初始隧道令牌（`ntk_...`）并一次性展示完整密钥，复制后即可直接配置 CLI。
2. **无人值守自动初始化**：若在 `.env` 中预设 `NERUTON_ADMIN_USER` 与 `NERUTON_ADMIN_PASSWORD`（至少 8 位），服务端首次启动（用户列表为空时）会自动创建该管理员账户与初始令牌；此后直接访问 `/login` 登录即可。
3. **管理令牌与鉴权策略**：
   - 登录控制台后，在 **令牌 (`/tokens`)** 页面随时创建、限制允许前缀（`allowed_prefixes`）、启用/禁用或撤销隧道令牌。
   - 在 **设置 (`/settings`)** 页面，管理员可以随时开启或关闭 **强制要求隧道 Token 鉴权**（默认开启）、配置单用户隧道配额和自定义保留前缀；所有用户均可在此修改个人密码或退出登录。
   - 在 **用户 (`/users`)** 页面，管理员可管理多用户账户与角色权限（`admin` / `user`）。

### 下载预编译客户端（Latest Release）

前往 [GitHub Releases Latest](https://github.com/kaecho/neruton/releases/latest) 下载对应平台的预编译包（每个压缩包均包含 `neruton` CLI 与 `neruton-server`），或使用以下命令快速安装：

**Linux (`x86_64`)**
```bash
curl -fsSL https://github.com/kaecho/neruton/releases/latest/download/neruton-x86_64-unknown-linux-gnu.tar.gz | tar -xz
sudo mv neruton /usr/local/bin/
neruton version
```

**Linux (`aarch64` / ARM64)**
```bash
curl -fsSL https://github.com/kaecho/neruton/releases/latest/download/neruton-aarch64-unknown-linux-gnu.tar.gz | tar -xz
sudo mv neruton /usr/local/bin/
```

**macOS (Apple Silicon `aarch64`)**
```bash
curl -fsSL https://github.com/kaecho/neruton/releases/latest/download/neruton-aarch64-apple-darwin.tar.gz | tar -xz
sudo mv neruton /usr/local/bin/
```

**macOS (Intel `x86_64`)**
```bash
curl -fsSL https://github.com/kaecho/neruton/releases/latest/download/neruton-x86_64-apple-darwin.tar.gz | tar -xz
sudo mv neruton /usr/local/bin/
```

**Windows (`x86_64`, PowerShell)**
```powershell
Invoke-WebRequest -Uri "https://github.com/kaecho/neruton/releases/latest/download/neruton-x86_64-pc-windows-msvc.zip" -OutFile "neruton.zip"
Expand-Archive -Path "neruton.zip" -DestinationPath ".\neruton" -Force
.\neruton\neruton.exe version
```

> 校验文件完整性可同时下载 `SHA256SUMS.txt` 并执行 `sha256sum -c SHA256SUMS.txt --ignore-missing`。

### 客户端快速上手（CLI）

1. **配置服务端地址与隧道令牌（推荐，默认开启令牌鉴权）**
   在 Web 控制台的 `/tokens` 页面创建令牌（格式为 `ntk_...`），然后写入本地配置 `~/.config/neruton/config.toml`（权限 `0600`）：
   ```bash
   neruton config set --server https://neruton.moer.eu.org --token ntk_your_token_here
   neruton config show
   ```
   > 也可以通过 `--token ntk_...` 参数或环境变量 `NERUTON_TOKEN` 按次传入。若服务端开启了强制令牌鉴权而未提供有效令牌，CLI 会收到 `401` 并打印明确提示后直接退出，不会无限重连刷屏。

2. **使用随机 UUID 前缀启动隧道（默认行为）**
   ```bash
   neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000
   ```
   启动后会分配唯一的随机 UUID 前缀，例如：
   - 泛域名地址：`https://<uuid>.moer.eu.org`
   - Web 预览面板：`https://neruton.moer.eu.org/preview/<uuid>`
   - 直接路径代理：`https://neruton.moer.eu.org/t/<uuid>/`

3. **指定自定义子域名前缀（`--subdomain` / `-s` / `--prefix`）**
   ```bash
   neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000 --subdomain test-test
   ```
   分配地址为 `https://test-test.moer.eu.org` 与 `https://neruton.moer.eu.org/preview/test-test`。
   > 若令牌配置了允许前缀白名单（`allowed_prefixes`），请使用白名单内的自定义前缀；同时禁止占用系统或自定义保留前缀。

4. **快捷命令 `neruton http`**
   ```bash
   # 将本机 3000 端口映射到随机 UUID 隧道（默认开启 DoH + Hidden SNI，自动使用已保存的 server 与 token）
   neruton http 3000

   # 将本机 8080 端口映射到自定义子域名 test-test
   neruton http 8080 -s test-test

   # 临时指定令牌连接
   neruton http 3000 --token ntk_your_token_here
   ```

### 隐蔽传输：默认 DoH 与 Hidden SNI

从客户端发起非本地 `wss://` 隧道连接时，Rust CLI、Python SDK 与 Node.js SDK 均**默认开启**两层传输隐蔽能力（`--doh auto --sni-mode auto`）：

1. **默认 DNS-over-HTTPS（RFC 8484，零引导 DNS 泄露）**
   - 直接向基于 IP 的 RFC 8484 DoH 端点发送二进制 POST（`application/dns-message`），内置端点为 `https://1.0.0.1/dns-query`、`https://223.5.5.5/dns-query`、`https://1.1.1.1/dns-query`、`https://8.8.4.4/dns-query`；先并行竞速前两个端点（约 3 秒超时）并依次回退，同时并发查询 `A`、`AAAA` 与 `HTTPS`（Type 65）记录，避免首次解析触发明文 UDP/53 引导查询。
   - 对 `localhost`、`*.localhost`、`*.local`、IPv4/IPv6 字面量以及明文 `ws://` 连接**自动跳过**，不影响本地开发与内网调试。
   - 在默认 `auto` 模式下，若所有 DoH 端点均不可达（例如离线局域网），客户端会输出告警并回退至系统 DNS；如需强制只走 DoH 可设为 `strict`（失败即报错），或通过 `--no-doh` / `off` 关闭并直接使用系统 DNS，也可通过 `--doh <URL,...>` 指定自定义 RFC 8484 端点。

2. **默认 SNI 隐藏（`--sni-mode auto`）与跨客户端能力对比**

   **Rust CLI、Python SDK 与 Node.js SDK 三端均原生实现真实加密 TLS 1.3 ECH（RFC 8446 + RFC 9180 HPKE + RFC 9849）**，各客户端的 SNI 隐藏行为一致如下：

   | 客户端 | 默认 `--sni-mode auto` 行为 | `--sni-mode ech` | `fragment` / `none` / `plain` 与 `--sni` |
   | --- | --- | --- | --- |
   | **Rust CLI (`neruton`)** | **真实加密 TLS 1.3 ECH**：自动通过 DoH `HTTPS` (Type 65) 记录获取 `ECHConfigList`（例如在 Cloudflare 节点上外层明文 SNI 仅为 `cloudflare-ech.com`，真实域名加密于内层 ClientHello，支持 RFC 9849 `retry_configs` 自动单次重试）；目标服务端未发布 ECH 记录时自动回退至 **ClientHello TCP 分片**。 | **原生支持（严格模式）**：纯 Rust HPKE（基于 `ring`，零 C/OpenSSL 依赖），无 ECH 配置或重试后仍被拒时快速失败。 | 全部支持；`none` / `--sni` 仍使用 WebPKI 针对真实目标主机名严格校验证书。 |
   | **Python SDK / CLI (`pip install neruton`)** | **真实加密 TLS 1.3 ECH**：原生实现 RFC 8446 TLS 1.3 + RFC 9180 HPKE + RFC 9849 ECH（基于 `cryptography>=42.0.0`，支持 Python 3.9–3.14 及 Colab / Kaggle，完整 RFC 5280 X.509 证书校验与自动单次 `retry_configs` 重试）；目标服务端未发布 ECH 记录时自动回退至 **ClientHello TCP 分片**。 | **原生支持（严格模式）**：需 DoH `HTTPS` 记录或 `--ech-config`，无 ECH 配置或单次 `retry_configs` 重试后仍被拒时快速失败（绝不以明文 SNI 发送令牌或应用数据）。 | 全部支持；`none` / `--sni` 通过纯 Python RFC 6125 严格校验真实主机名证书。 |
   | **Node.js / TS SDK / CLI (`npm install neruton`)** | **真实加密 TLS 1.3 ECH**：纯 TypeScript 原生实现 RFC 8446 TLS 1.3 + RFC 9180 HPKE + RFC 9849 ECH（仅用内置 `node:crypto` + `node:tls`，零额外 npm 依赖，Node.js >= 18，完整 X.509 证书校验与自动单次 `retry_configs` 重试）；目标服务端未发布 ECH 记录时自动回退至 **ClientHello TCP 分片**。 | **原生支持（严格模式）**：需 DoH `HTTPS` 记录或 `--ech-config`，无 ECH 配置或单次 `retry_configs` 重试后仍被拒时快速失败（绝不以明文 SNI 发送令牌或应用数据）。 | 全部支持；`none` / `--sni` 通过 `tls.checkServerIdentity` 针对真实主机名严格校验证书。 |

   **`--sni-mode` 模式说明**：
   - `auto`（默认）：三端客户端（Rust CLI / Python SDK / Node.js SDK）均优先启用真 TLS 1.3 ECH（含 RFC 9849 自动单次 `retry_configs` 重试），目标服务端未发布 ECH 记录时自动回退至 ClientHello TCP 分片。
   - `ech`：严格 TLS 1.3 ECH（三端均原生支持；需 DoH `HTTPS` 记录或 `--ech-config`，不可用或重试后仍被拒时快速失败）。
   - `fragment`：强制将初始 TLS ClientHello 分片发送（`TCP_NODELAY`），兼容 Cloudflare 且完整校验证书。
   - `none`：完全省略 TLS SNI 扩展，但仍严格按真实主机名校验证书（适合不要求 SNI 的自建服务端；注意 Cloudflare 边缘会拒绝无 SNI 握手）。
   - `plain`：标准明文 SNI，不做隐藏或分片。
   - 配合 `--sni <HOST>` 可发送自定义 SNI 主机名（除非同时指定 `--no-tls-verify`，否则证书仍严格按真实服务端主机名校验）；配合 `--ech-config <BASE64>` 可手动传入 Base64 编码的 `ECHConfigList`，三端客户端均直接用于覆盖 DoH `HTTPS` 记录执行 TLS 1.3 ECH。

3. **统一 CLI 参数、环境变量与 `config.toml` 配置**

   三端客户端共享完全一致的参数与配置文件，优先级严格遵循：**显式 CLI 参数 / SDK 传参 > 环境变量 > `~/.config/neruton/config.toml` > 默认值（`doh = "auto"`、`sni_mode = "auto"`）**。

   | 配置项 | CLI 参数（`tunnel` / `http` / `config set`） | 环境变量 | `config.toml` 键名 | 默认值 |
   | --- | --- | --- | --- | --- |
   | 服务端地址 | `--server <URL>` | `NERUTON_SERVER` | `server` | `https://neruton.moer.eu.org` |
   | 隧道令牌 | `--token <TOKEN>` | `NERUTON_TOKEN`（兼容 `NERUTON_AUTH_TOKEN`） | `token` | *(无)* |
   | DoH 模式/端点 | `--doh <auto\|strict\|off\|URL,...>` / `--no-doh` | `NERUTON_DOH` | `doh` | `"auto"` |
   | SNI 隐藏模式 | `--sni-mode <auto\|ech\|fragment\|none\|plain>` | `NERUTON_SNI_MODE` | `sni_mode` | `"auto"` |
   | 自定义 SNI | `--sni <HOST>` | `NERUTON_SNI` | `sni` | *(无)* |
   | 手动 ECH 配置 | `--ech-config <BASE64>` | `NERUTON_ECH_CONFIG` | `ech_config` | *(通过 DoH 自动获取)* |

   ```bash
   # 将 DoH 与 SNI 策略写入共享配置 ~/.config/neruton/config.toml 并查看生效配置
   neruton config set --doh strict --sni-mode auto
   neruton config show

   # 按次覆盖：强制严格 DoH + 真 TLS 1.3 ECH（Rust / Python / Node 三端均支持）
   neruton http 3000 --doh strict --sni-mode ech

   # 按次覆盖：自定义 DoH 端点列表 + ClientHello 分片
   neruton tunnel --url http://127.0.0.1:3000 \
     --doh https://1.0.0.1/dns-query,https://223.5.5.5/dns-query \
     --sni-mode fragment

   # 关闭 DoH 与 SNI 隐藏（等同传统直连模式）
   neruton http 3000 --no-doh --sni-mode plain
   ```

   `~/.config/neruton/config.toml` 示例（所有键值均为纯字符串，Rust / Python / Node.js 三端完全互通）：

   ```toml
   server = "https://neruton.moer.eu.org"
   token = "ntk_your_token_here"
   doh = "auto"        # "auto" | "strict" | "off" | "https://1.0.0.1/dns-query,..."
   sni_mode = "auto"   # "auto" | "ech" | "fragment" | "none" | "plain"
   # sni = "moer.eu.org"
   # ech_config = "<base64-ECHConfigList>"
   ```

### Python SDK 与 CLI（`pip install neruton`）

[`packages/python/`](packages/python/README.md) 提供纯 Python 原生实现的 Neruton 客户端（无需打包 Rust 二进制，基于 `cryptography>=42.0.0`，支持 Python 3.9–3.14 及 Google Colab / Kaggle，内置完整 `py.typed` 类型标注），默认开启 **RFC 8484 DoH + 真 TLS 1.3 ECH（RFC 8446 + RFC 9180 HPKE + RFC 9849）**（支持自动单次 `retry_configs` 重试，目标服务端无 ECH 记录时自动回退至 ClientHello TCP 分片），可直接在异步或同步 Python 应用中通过 `import neruton` 拉起隧道，也可作为 CLI 运行。

```bash
pip install neruton
```

**异步 API（`asyncio` / FastAPI / Starlette / aiohttp）**

```python
import asyncio
import neruton

async def main() -> None:
    async with neruton.connect(
        url="http://127.0.0.1:3000",
        server="https://neruton.moer.eu.org",  # 可选，默认读取 NERUTON_SERVER / config.toml
        token="ntk_your_token_here",           # 可选，默认读取 NERUTON_TOKEN / config.toml
        subdomain="my-app",                    # 可选，省略时自动分配 UUID v4
        doh="auto",                            # 可选："auto" | "strict" | "off" | bool | Sequence[str]
        sni_mode="auto",                       # 可选："auto" | "ech" | "fragment" | "none" | "plain"
        # sni="moer.eu.org",                   # 可选：自定义 SNI（仍按真实主机名做 RFC 6125 证书校验）
        # ech_config="...",                    # 可选：Base64 编码的 ECHConfigList（覆盖 DoH HTTPS 记录）
        on_warn=lambda msg: print("WARN:", msg),
    ) as tunnel:
        print("Public URL :", tunnel.public_url)
        print("Preview URL:", tunnel.preview_url)
        print("Path URL   :", tunnel.path_url)
        print("Prefix     :", tunnel.prefix)
        print("Transport  :", tunnel.transport_info.summary() if tunnel.transport_info else None)
        await tunnel.wait()

asyncio.run(main())
```

常用端口快捷方式：`async with neruton.forward(3000, subdomain="my-app", doh="strict", sni_mode="ech") as tunnel:` 或 `tunnel = await neruton.http(8080, doh=False, sni_mode="plain")`（退出时调用 `await tunnel.close()`）；DoH 严格模式失败时抛出 `neruton.DohError`，严格 `sni_mode="ech"` 在缺少有效 ECH 配置或单次 `retry_configs` 重试后仍被拒时抛出 `neruton.TunnelError`。

**同步 API（Flask / Django / 脚本 / Notebook）**

`neruton.open(...)` 会在后台守护线程中运行事件循环（同样接受 `doh`、`sni_mode`、`sni`、`ech_config`、`on_warn`），退出 `with` 代码块时自动优雅关闭隧道：

```python
import neruton

with neruton.open(5000, server="https://neruton.moer.eu.org", token="ntk_your_token_here") as tunnel:
    print("Tunnel live at:", tunnel.public_url)
    app.run(port=5000)
```

**CLI 与共享配置（`~/.config/neruton/config.toml`）**

Python SDK 与 Rust CLI 完全共享 `~/.config/neruton/config.toml`（写入权限 `0600`）及环境变量 `NERUTON_SERVER`、`NERUTON_TOKEN`（兼容 `NERUTON_AUTH_TOKEN`）、`NERUTON_DOH`、`NERUTON_SNI_MODE`、`NERUTON_SNI`、`NERUTON_ECH_CONFIG`，并提供 `neruton.config_path()`、`neruton.load_config()`、`neruton.save_config(server=..., token=..., doh=..., sni_mode=..., sni=..., ech_config=...)` 与 `neruton.resolve_stealth_options()` 等导出函数：

```bash
neruton config set --server https://neruton.moer.eu.org --token ntk_your_token_here --doh auto --sni-mode auto
neruton config show
neruton config path

neruton http 3000
neruton tunnel --url http://127.0.0.1:3000 --subdomain my-app --doh strict --sni-mode ech
python -m neruton http 3000 --no-doh --sni-mode plain
python -m neruton version
```

### Node.js / TypeScript SDK 与 CLI（`npm install neruton`）

[`packages/node/`](packages/node/README.md) 提供纯 Node.js / TypeScript 原生实现的 Neruton 客户端（无需打包 Rust 二进制，仅依赖内置 `node:crypto` + `node:tls` 实现 ECH，零额外 npm 依赖，要求 Node.js >= 18），默认开启 **RFC 8484 DoH + 真 TLS 1.3 ECH（RFC 8446 + RFC 9180 HPKE + RFC 9849）**（支持自动单次 `retry_configs` 重试，目标服务端无 ECH 记录时自动回退至 ClientHello TCP 分片），同时支持 ESM 与 CommonJS 并附带完整 `.d.ts` 类型声明。

```bash
# 作为项目依赖安装
npm install neruton

# 或全局安装 CLI
npm install -g neruton
```

**ESM / TypeScript API**

```ts
import { connect, forward, http, DohError } from 'neruton';

const tunnel = await connect({
  url: 'http://127.0.0.1:3000',
  server: 'https://neruton.moer.eu.org', // 可选，默认读取 NERUTON_SERVER / config.toml
  token: process.env.NERUTON_TOKEN,      // 可选，默认读取 NERUTON_TOKEN / config.toml
  subdomain: 'my-app',                   // 可选，省略时自动分配 UUID v4
  doh: 'auto',                           // 可选：'auto' | 'strict' | 'off' | boolean | string[]
  sniMode: 'auto',                       // 可选：'auto' | 'ech' | 'fragment' | 'none' | 'plain'
  // sni: 'moer.eu.org',                 // 可选：自定义 SNI（仍按真实主机名严格校验证书）
  // echConfig: '...',                   // 可选：Base64 编码的 ECHConfigList（覆盖 DoH HTTPS 记录）
  onWarning: (msg) => console.warn(msg),
});

console.log('Public URL :', tunnel.publicUrl);
console.log('Preview URL:', tunnel.previewUrl);
console.log('Path URL   :', tunnel.pathUrl);
console.log('Prefix     :', tunnel.prefix);
console.log('Transport  :', tunnel.transportInfo?.summary);

tunnel.on('request', ({ method, path, status, durationMs }) => {
  console.log(`${status} ${method} ${path} (${durationMs}ms)`);
});

tunnel.on('reconnecting', ({ attempt, delayMs, reason }) => {
  console.warn(`Reconnect #${attempt} in ${delayMs}ms (${reason})`);
});

tunnel.on('warning', (message) => {
  console.warn(`Warning: ${message}`);
});

// 使用完毕后关闭，也支持 `await using tunnel = await forward(3000)` 自动释放（Symbol.asyncDispose）
await tunnel.close();
```

**CommonJS API**

```js
const { connect, forward, http, loadConfig, saveConfig, configPath } = require('neruton');

async function main() {
  const tunnel = await forward(3000, {
    server: 'https://neruton.moer.eu.org',
    token: 'ntk_your_token_here',
    doh: 'strict',
    sniMode: 'ech',
  });
  console.log('Online at', tunnel.publicUrl, '|', tunnel.transportInfo?.summary);
  await tunnel.close();
}

main();
```

**CLI 与共享配置（`~/.config/neruton/config.toml`）**

Node.js SDK 同样完全兼容 `~/.config/neruton/config.toml`（写入权限 `0600`）与 `NERUTON_SERVER`、`NERUTON_TOKEN`（及 `NERUTON_AUTH_TOKEN`）、`NERUTON_DOH`、`NERUTON_SNI_MODE`、`NERUTON_SNI`、`NERUTON_ECH_CONFIG`，并提供 `configPath()`、`loadConfig()`、`saveConfig({ server, token, doh, sniMode, sni, echConfig })`、`resolveConnectionSettings()` 与 `DohError` 等导出：

```bash
neruton config set --server https://neruton.moer.eu.org --token ntk_your_token_here --doh auto --sni-mode auto
neruton config show
neruton config path

neruton http 3000
neruton http 3000 -s my-app --doh strict --sni-mode ech
neruton tunnel --url http://127.0.0.1:3000 --subdomain my-app --no-doh --sni-mode plain
neruton version
```

### 服务端部署（Docker Compose + `cloudflared`，零端口暴露）

1. **准备环境变量**
   ```bash
   git clone https://github.com/kaecho/neruton.git
   cd neruton
   cp .env.example .env
   ```

2. **创建 Cloudflare Tunnel 并配置远程 Ingress**
   在 Cloudflare Zero Trust 控制台（或使用 `cf` CLI）创建远程托管隧道，配置两条路由指向容器内部地址 `http://neruton-server:8080`：
   - `neruton.moer.eu.org` -> `http://neruton-server:8080`
   - `*.moer.eu.org` -> `http://neruton-server:8080`
   - 兜底规则：`http_status:404`

   同时在 Cloudflare DNS 为 `neruton.moer.eu.org` 和 `*.moer.eu.org` 添加开启代理（Proxied）的 `CNAME` 记录指向 `<tunnel-id>.cfargotunnel.com`。
   > 提示：根据 RFC 1034，同一通配符名称 `*.moer.eu.org` 下若存在 `MX` 记录会与 `CNAME` 冲突，配置泛域名 `CNAME` 前需清理冲突的通配符记录（根域名 `moer.eu.org` 的记录不受影响）。

3. **填入 Token 并拉取预构建镜像启动（无需在服务器编译）**
   编辑 `.env`，填入 `CLOUDFLARED_TUNNEL_TOKEN`（按需调整 `NERUTON_REQUIRE_AUTH`、`NERUTON_ADMIN_PASSWORD` 等），直接拉取 GHCR 多架构镜像（`linux/amd64` + `linux/arm64`）并启动：
   ```bash
   docker compose pull && docker compose up -d
   docker compose ps
   ```
   镜像地址：
   - `ghcr.io/kaecho/neruton-server:latest`
   - `ghcr.io/kaecho/neruton-web:latest`

   整个栈仅使用内部桥接网络 `neruton-net`，宿主机 **0 端口监听**。`neruton-server` 通过命名卷 `neruton-data:/data` 持久化存储 `/data/state.json`，镜像升级与容器重建时不会丢失用户账户、隧道令牌与系统配置（请勿随意使用 `docker compose down -v`）。

4. **本地源码构建调试模式（无需 Cloudflare）**
   如需在本地从源码构建验证，可使用附带的覆盖文件仅在 `127.0.0.1:8080` 暴露服务端、跳过 `cloudflared`，并同样通过 `neruton-data:/data` 卷与鉴权环境变量保持与生产一致：
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.local.yml up --build
   ```

### 环境变量说明

**服务端环境变量**（客户端环境变量 `NERUTON_SERVER`、`NERUTON_TOKEN`、`NERUTON_DOH`、`NERUTON_SNI_MODE`、`NERUTON_SNI`、`NERUTON_ECH_CONFIG` 请见上方「[隐蔽传输：默认 DoH 与 Hidden SNI](#隐蔽传输默认-doh-与-hidden-sni)」）：

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `NERUTON_IMAGE_TAG` | `latest` | GHCR 镜像标签（如 `latest`、`v0.4.0`） |
| `NERUTON_BASE_DOMAIN` | `moer.eu.org` | 泛域名根域（`<prefix>.<NERUTON_BASE_DOMAIN>`） |
| `NERUTON_PANEL_HOST` | `neruton.moer.eu.org` | Web 控制台与隧道 WSS 接入域名 |
| `NERUTON_PUBLIC_SCHEME` | `https` | 对外协议方案（`https` 或 `http`），同时决定会话 Cookie 是否附加 `Secure` |
| `NERUTON_DATA_DIR` | `/data`（容器）/ `./data`（二进制） | 持久化数据目录，保存 `state.json` |
| `NERUTON_REQUIRE_AUTH` | `true` | 初始化新状态时是否默认强制要求隧道 Token 鉴权（后续可在 Web `/settings` 在线切换并持久化） |
| `NERUTON_ADMIN_USER` | `admin` | 自动初始化管理员时使用的用户名 |
| `NERUTON_ADMIN_PASSWORD` | *(空)* | 可选：预设管理员密码（至少 8 位）以在空状态启动时自动初始化；留空则通过 Web UI 完成首次初始化 |
| `NERUTON_SESSION_SECRET` | *(空)* | 可选：Web 会话 Cookie 的 HMAC-SHA256 签名密钥；留空时自动生成 32 字节随机十六进制密钥并持久化至 `state.json` |
| `NERUTON_AUTH_TOKEN` | *(空)* | 可选：兼容旧版的全局主隧道 Bearer Token（与每用户 `ntk_...` 令牌并存） |
| `CLOUDFLARED_TUNNEL_TOKEN` | *(必填)* | Cloudflare Tunnel Token（生产部署） |

---

## English Documentation

### Highlights (v0.4.0)

- **WSS + Yamux over Port 443**: `neruton` opens a single outbound WebSocket (`wss://`) connection and multiplexes concurrent HTTP/1.1 & WebSocket streams via **Yamux**, traversing NATs, strict corporate firewalls, and Cloudflare proxies effortlessly.
- **Default Stealth Transport (RFC 8484 DoH + True TLS 1.3 ECH)**: Non-local `wss://` connections default to IP-based **DNS-over-HTTPS** (zero bootstrap plaintext DNS leak; auto-skips `localhost`, `.local`, and IP literals) paired with **Hidden SNI (`--sni-mode auto`)**—**all three clients (Rust CLI, Python SDK, and Node.js SDK)** natively perform **true cryptographic TLS 1.3 ECH (RFC 8446 + RFC 9180 HPKE + RFC 9849)** via DoH `HTTPS` (Type 65) records with automatic 1-shot `retry_configs` retry, automatically falling back to ClientHello TCP fragmentation when the server publishes no ECH record, with full TLS 1.3 certificate verification throughout.
- **Wildcard Subdomain Routing**: Assigns an automatic lowercase UUID v4 subdomain by default (`https://<uuid>.moer.eu.org`) or a custom subdomain via `--subdomain test-test` (`https://test-test.moer.eu.org`).
- **No-Extra-Domain Web Viewer (`/preview/<prefix>` & `/t/<prefix>/`)**: Inspect tunneled web services directly inside the dashboard's embedded browser viewport at `/preview/<prefix>` without binding additional domains. `neruton-server` serves `/t/<prefix>/` with frame-header relaxation, relative redirect rewriting, and automatic HTML `<base>` injection.
- **Web Account Authentication & Multi-User RBAC**:
  - Supports interactive first-run administrator setup in the Web UI (or unattended bootstrap via environment variables), pure-Rust **Argon2** password hashing, and HMAC-SHA256 signed `HttpOnly` session cookies (`neruton_session`).
  - Role-based access control (`admin` / `user`): admins manage accounts in `/users` (create, enable/disable, change role, reset password, delete); regular users only see and manage their own tunnels, tokens, and traffic logs.
- **Per-User Tunnel Tokens & Live-Toggleable Enforcement (ON by Default)**:
  - Tunnel token authentication (`require_tunnel_auth`) is **enabled by default** (`NERUTON_REQUIRE_AUTH=true`).
  - Users create scoped tokens (`ntk_...`) in `/tokens` with optional `allowed_prefixes` restrictions; raw secrets are displayed once and stored only as SHA-256 hashes.
  - Disabling or revoking a token immediately disconnects active tunnels using it. Admins can toggle `require_tunnel_auth` ON/OFF live in `/settings` (persisted in `/data/state.json`). Optional legacy/master `NERUTON_AUTH_TOKEN` remains supported.
- **Reserved Prefixes & User Quotas**: Protects built-in prefixes (`neruton`, `www`, `api`, `admin`, `_neruton`, plus the panel subdomain) and lets admins configure custom `reserved_prefixes` and `max_tunnels_per_user` in `/settings`.
- **Zero-Exposed-Port Deployment & Persistent `/data` Volume**: Production `docker-compose.yml` pairs `neruton-server` and `neruton-web` with an outbound `cloudflared` connector on an internal bridge network (`neruton-net`)—no host ports are opened—and persists accounts, hashed tokens, session secret, and settings atomically in the named `neruton-data` volume mounted at `/data`.
- **Pure-Rust TLS (`rustls` + Native TLS 1.3 ECH) & Multi-Platform Releases**: Zero OpenSSL/C dependencies (including pure-Rust RFC 9180 HPKE over `ring` for ECH); every `v*` git tag builds Linux (`x86_64`, `aarch64`), macOS (`aarch64`, `x86_64`), and Windows (`x86_64`) binaries and publishes them to [GitHub Releases (`latest`)](https://github.com/kaecho/neruton/releases/latest).
- **Native Python & Node.js / TypeScript SDKs**: Alongside the Rust CLI, native Python (`pip install neruton`, using `cryptography>=42.0.0`, supporting Python 3.9–3.14 including Google Colab & Kaggle) and pure-Node.js/TypeScript (`npm install neruton`, using only built-in `node:crypto` + `node:tls` with zero extra npm dependencies on Node >= 18) clients implement the exact WSS + Yamux v0 wire protocol and **true TLS 1.3 ECH** natively—embeddable via `import`/`require` or runnable as drop-in CLIs sharing `~/.config/neruton/config.toml`.

### Architecture

```text
Local App (:3000) <--> neruton CLI ==[ WSS + Yamux (:443) ]==> Cloudflare Edge
                         (ntk_ token)                                 |
                                                             cloudflared (outbound)
                                                                      | (neruton-net)
                                                              neruton-server (:8080) ---> neruton-data (/data/state.json)
                                                             /                      \
                                      *.<base_domain> & /t/*                        /* (Panel & /preview/*)
                                         (Yamux tunnel)                              neruton-web (:3000)
```

### First-Run Setup & Web Account Login

After starting the stack, open the dashboard (e.g. `https://neruton.moer.eu.org`):

1. **Interactive Web Setup (Default)**: Leave `NERUTON_ADMIN_PASSWORD` empty in `.env`. On first visit, the panel presents the administrator initialization form, creates the first `admin` account (password >= 8 chars), and displays a one-time `Default CLI Token` (`ntk_...`) ready to configure the CLI.
2. **Unattended Bootstrap**: Set `NERUTON_ADMIN_USER` and `NERUTON_ADMIN_PASSWORD` (>= 8 chars) in `.env` before first startup to seed the admin account and an initial token automatically, then sign in at `/login`.
3. **Managing Tokens, Users & Policies**:
   - **`/tokens`**: Create per-user `ntk_...` tokens with optional `allowed_prefixes`, toggle enabled state, or revoke tokens (immediately disconnecting active sessions).
   - **`/users` (Admin)**: Create and manage `admin` / `user` accounts, reset passwords, or disable users.
   - **`/settings`**: Admins live-toggle **Require Tunnel Token Auth** (`require_tunnel_auth`), configure `max_tunnels_per_user`, and edit custom `reserved_prefixes`; all users can change their own password or sign out.

### Download Prebuilt Binaries

Download the latest release archive (containing both `neruton` CLI and `neruton-server`) from [https://github.com/kaecho/neruton/releases/latest](https://github.com/kaecho/neruton/releases/latest):

| Platform | Asset |
| --- | --- |
| Linux `x86_64` | `neruton-x86_64-unknown-linux-gnu.tar.gz` |
| Linux `aarch64` | `neruton-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple Silicon | `neruton-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `neruton-x86_64-apple-darwin.tar.gz` |
| Windows `x86_64` | `neruton-x86_64-pc-windows-msvc.zip` |

Quick install on Linux `x86_64`:
```bash
curl -fsSL https://github.com/kaecho/neruton/releases/latest/download/neruton-x86_64-unknown-linux-gnu.tar.gz | tar -xz
sudo install -m 755 neruton /usr/local/bin/neruton
```

Or build from source (Rust 1.83+):
```bash
cargo build --release --bin neruton --bin neruton-server
```

### Quick Start (CLI)

```bash
# 1. Save your server URL & tunnel token created in Web UI (/tokens)
#    Stored in ~/.config/neruton/config.toml (mode 0600 on Unix)
neruton config set --server https://neruton.moer.eu.org --token ntk_your_token_here
neruton config show

# 2. Start a tunnel with an auto-generated UUID v4 prefix
neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000

# 3. Start a tunnel with a custom subdomain (test-test.moer.eu.org)
neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000 --subdomain test-test

# 4. Shorthand for local HTTP ports (DoH + Hidden SNI ON by default; reuses saved server & token)
neruton http 3000
neruton http 8080 -s test-test
neruton http 3000 --token ntk_your_token_here
```

> With tunnel token authentication enabled by default, `neruton` exits cleanly with a clear error on `401` instead of looping reconnects if the token is missing, invalid, or revoked.

### Stealth Transport: Default DoH & Hidden SNI

For non-local `wss://` tunnel connections, all three clients (Rust CLI, Python SDK, and Node.js SDK) enable stealth transport **by default** (`--doh auto --sni-mode auto`):

1. **Default DNS-over-HTTPS (RFC 8484, Zero Bootstrap DNS Leak)**
   - Sends RFC 8484 binary POST (`application/dns-message`) directly to IP-based endpoints—`https://1.0.0.1/dns-query`, `https://223.5.5.5/dns-query`, `https://1.1.1.1/dns-query`, and `https://8.8.4.4/dns-query`—eliminating plaintext UDP/53 bootstrap queries. The first two endpoints race in parallel (~3s timeout) with automatic fallback across the remaining endpoints, querying `A`, `AAAA`, and `HTTPS` (Type 65) records concurrently.
   - Automatically skipped for `localhost`, `*.localhost`, `*.local`, IPv4/IPv6 literals, and non-TLS `ws://` connections so local development and testing stay fast and offline-safe.
   - In default `auto` mode, if all DoH endpoints are unreachable (e.g. an air-gapped LAN), the client logs a warning and falls back to system DNS. Use `--doh strict` (`doh="strict"`) to fail closed instead of falling back, `--doh <URL,...>` for custom RFC 8484 endpoints, or `--no-doh` (`doh="off"` / `False` / `false`) to use system DNS directly.

2. **Default Hidden SNI (`--sni-mode auto`) & Cross-Client Comparison**

   **All three clients (Rust CLI, Python SDK, and Node.js SDK)** natively implement **true cryptographic TLS 1.3 ECH (RFC 8446 + RFC 9180 HPKE + RFC 9849)** by default, with consistent SNI hiding across runtimes:

   | Client | Default `--sni-mode auto` Behavior | `--sni-mode ech` | `fragment` / `none` / `plain` & `--sni` |
   | --- | --- | --- | --- |
   | **Rust CLI (`neruton`)** | **True cryptographic TLS 1.3 ECH**: fetches `ECHConfigList` via DoH `HTTPS` (Type 65) record (e.g. outer wire SNI is `cloudflare-ech.com` on Cloudflare while the real hostname is encrypted inside the inner ClientHello, with automatic 1-shot RFC 9849 `retry_configs` retry). Automatically falls back to **ClientHello TCP fragmentation** when the server publishes no ECH record. | **Supported (strict)**: pure-Rust RFC 9180 HPKE over `ring` (zero C/OpenSSL deps); fails fast if no ECH config is available or ECH is rejected after retry. | All supported; `none` and `--sni` strictly verify the server certificate against the real gateway hostname via WebPKI. |
   | **Python SDK / CLI (`pip install neruton`)** | **True cryptographic TLS 1.3 ECH**: native RFC 8446 TLS 1.3 + RFC 9180 HPKE + RFC 9849 ECH using `cryptography>=42.0.0` (works on Python 3.9–3.14 including Google Colab & Kaggle), with strict RFC 5280 X.509 certificate verification and automatic 1-shot `retry_configs` retry. Automatically falls back to **ClientHello TCP fragmentation** when the server publishes no ECH record. | **Supported (strict)**: requires DoH `HTTPS` record or `--ech-config`; fails fast if no compatible ECH config is available or ECH is rejected after 1-shot `retry_configs` retry (never sends tokens or application data over plaintext SNI). | All supported; `none` and `--sni` perform strict pure-Python RFC 6125 certificate verification against the real hostname. |
   | **Node.js / TS SDK / CLI (`npm install neruton`)** | **True cryptographic TLS 1.3 ECH**: pure-TypeScript RFC 8446 TLS 1.3 + RFC 9180 HPKE + RFC 9849 ECH using only built-in `node:crypto` + `node:tls` (zero extra npm deps, Node >= 18), with strict X.509 certificate verification and automatic 1-shot `retry_configs` retry. Automatically falls back to **ClientHello TCP fragmentation** when the server publishes no ECH record. | **Supported (strict)**: requires DoH `HTTPS` record or `--ech-config`; fails fast if no compatible ECH config is available or ECH is rejected after 1-shot `retry_configs` retry (never sends tokens or application data over plaintext SNI). | All supported; `none` and `--sni` enforce strict `tls.checkServerIdentity` verification against the real hostname. |

   **`--sni-mode` values**:
   - `auto` *(default)*: All three clients (Rust CLI, Python SDK, and Node.js SDK) use **true TLS 1.3 ECH** (with automatic 1-shot `retry_configs` retry) whenever the server publishes an ECH record or `--ech-config` is supplied, automatically falling back to **ClientHello TCP fragmentation** when no ECH record is published.
   - `ech`: Strict **true TLS 1.3 ECH** (natively supported across all three clients; requires a DoH `HTTPS` record or `--ech-config`, failing fast if unavailable or rejected after retry).
   - `fragment`: Splits the initial TLS ClientHello record across TCP segments (`TCP_NODELAY`); Cloudflare-compatible with full TLS 1.3 certificate verification.
   - `none`: Omits the TLS SNI extension while still verifying the certificate against the real host (useful for self-hosted servers that do not require SNI; note that Cloudflare-fronted endpoints reject omitted SNI with `handshake_failure`).
   - `plain`: Standard TLS SNI with no hiding or fragmentation.
   - `--sni <HOST>` sends a custom SNI hostname while strictly validating the certificate against the real server host (unless `--no-tls-verify` is set). `--ech-config <BASE64>` supplies an explicit base64-encoded TLS 1.3 `ECHConfigList`, used directly across all three clients to override DoH `HTTPS` records for TLS 1.3 ECH.

3. **Unified CLI Flags, Env Vars & `config.toml` Keys**

   All three clients share the same options and config schema with strict precedence: **Explicit CLI flag / SDK arg > Environment variable > `~/.config/neruton/config.toml` > Defaults (`doh = "auto"`, `sni_mode = "auto"`)**.

   | Setting | CLI Flag (`tunnel` / `http` / `config set`) | Environment Variable | `config.toml` Key | Default |
   | --- | --- | --- | --- | --- |
   | Server | `--server <URL>` | `NERUTON_SERVER` | `server` | `https://neruton.moer.eu.org` |
   | Token | `--token <TOKEN>` | `NERUTON_TOKEN` (compat: `NERUTON_AUTH_TOKEN`) | `token` | — |
   | DoH | `--doh <auto\|strict\|off\|URL,...>` / `--no-doh` | `NERUTON_DOH` | `doh` | `"auto"` |
   | SNI Mode | `--sni-mode <auto\|ech\|fragment\|none\|plain>` | `NERUTON_SNI_MODE` | `sni_mode` | `"auto"` |
   | Custom SNI | `--sni <HOST>` | `NERUTON_SNI` | `sni` | — |
   | ECH Config | `--ech-config <BASE64>` | `NERUTON_ECH_CONFIG` | `ech_config` | *(auto via DoH)* |

   ```bash
   # Persist stealth transport defaults to ~/.config/neruton/config.toml and inspect effective settings
   neruton config set --doh strict --sni-mode auto
   neruton config show

   # Per-invocation overrides: strict DoH + true cryptographic TLS 1.3 ECH (Rust / Python / Node)
   neruton http 3000 --doh strict --sni-mode ech

   # Custom RFC 8484 DoH endpoints + ClientHello TCP fragmentation
   neruton tunnel --url http://127.0.0.1:3000 \
     --doh https://1.0.0.1/dns-query,https://223.5.5.5/dns-query \
     --sni-mode fragment

   # Disable DoH and SNI hiding (plain system DNS + standard TLS SNI)
   neruton http 3000 --no-doh --sni-mode plain
   ```

   Example `~/.config/neruton/config.toml` (string-only keys for full Rust / Python / Node.js interop):

   ```toml
   server = "https://neruton.moer.eu.org"
   token = "ntk_your_token_here"
   doh = "auto"        # "auto" | "strict" | "off" | "https://1.0.0.1/dns-query,..."
   sni_mode = "auto"   # "auto" | "ech" | "fragment" | "none" | "plain"
   # sni = "moer.eu.org"
   # ech_config = "<base64-ECHConfigList>"
   ```

### Python SDK (`pip install neruton`)

[`packages/python/`](packages/python/README.md) is a native pure-Python implementation of the Neruton tunnel client (no bundled Rust binary, built on `cryptography>=42.0.0`, works on Python 3.9–3.14 including Google Colab & Kaggle, PEP 561 `py.typed`), with **RFC 8484 DoH + true TLS 1.3 ECH (RFC 8446 + RFC 9180 HPKE + RFC 9849)** enabled by default (including automatic 1-shot `retry_configs` retry and ClientHello TCP fragmentation fallback when no ECH record is published), usable programmatically via `import neruton` or as a CLI.

```bash
pip install neruton
```

**Async API (`asyncio` / FastAPI / Starlette / aiohttp)**

```python
import asyncio
import neruton

async def main() -> None:
    async with neruton.connect(
        url="http://127.0.0.1:3000",
        server="https://neruton.moer.eu.org",  # optional; reads NERUTON_SERVER / config.toml
        token="ntk_your_token_here",           # optional; reads NERUTON_TOKEN / config.toml
        subdomain="my-app",                    # optional; auto-assigns UUID v4 if omitted
        doh="auto",                            # optional: "auto" | "strict" | "off" | bool | Sequence[str]
        sni_mode="auto",                       # optional: "auto" | "ech" | "fragment" | "none" | "plain"
        # sni="moer.eu.org",                   # optional custom SNI (cert still checked via RFC 6125)
        # ech_config="...",                    # optional base64 ECHConfigList (overrides DoH HTTPS record)
        on_warn=lambda msg: print("WARN:", msg),
    ) as tunnel:
        print("Public URL :", tunnel.public_url)
        print("Preview URL:", tunnel.preview_url)
        print("Path URL   :", tunnel.path_url)
        print("Prefix     :", tunnel.prefix)
        print("Transport  :", tunnel.transport_info.summary() if tunnel.transport_info else None)
        await tunnel.wait()

asyncio.run(main())
```

Shorthands for local ports: `async with neruton.forward(3000, subdomain="my-app", doh="strict", sni_mode="ech") as tunnel:` or `tunnel = await neruton.http(8080, doh=False, sni_mode="plain")` (close with `await tunnel.close()`). Strict DoH failures raise `neruton.DohError`; strict `sni_mode="ech"` raises `neruton.TunnelError` if no compatible ECH config is available or ECH is rejected after 1-shot `retry_configs` retry.

**Sync API (Flask / Django / Scripts / Notebooks)**

`neruton.open(...)` runs the event loop on a dedicated daemon thread (supporting the same `doh`, `sni_mode`, `sni`, `ech_config`, and `on_warn` arguments) and shuts down cleanly when exiting the `with` block:

```python
import neruton

with neruton.open(5000, server="https://neruton.moer.eu.org", token="ntk_your_token_here") as tunnel:
    print("Tunnel live at:", tunnel.public_url)
    app.run(port=5000)
```

**CLI & Shared Config (`~/.config/neruton/config.toml`)**

The Python SDK shares `~/.config/neruton/config.toml` (mode `0600` on POSIX) and `NERUTON_SERVER`, `NERUTON_TOKEN` (plus `NERUTON_AUTH_TOKEN`), `NERUTON_DOH`, `NERUTON_SNI_MODE`, `NERUTON_SNI`, and `NERUTON_ECH_CONFIG` with the Rust CLI, and exports `neruton.config_path()`, `neruton.load_config()`, `neruton.save_config(server=..., token=..., doh=..., sni_mode=..., sni=..., ech_config=...)`, and `neruton.resolve_stealth_options()`:

```bash
neruton config set --server https://neruton.moer.eu.org --token ntk_your_token_here --doh auto --sni-mode auto
neruton config show
neruton config path

neruton http 3000
neruton tunnel --url http://127.0.0.1:3000 --subdomain my-app --doh strict --sni-mode ech
python -m neruton http 3000 --no-doh --sni-mode plain
python -m neruton version
```

### Node.js / TypeScript SDK (`npm install neruton`)

[`packages/node/`](packages/node/README.md) is a native pure-Node.js / TypeScript implementation of the Neruton tunnel client (no bundled Rust binary, using only built-in `node:crypto` + `node:tls` for ECH with zero extra npm dependencies, Node.js >= 18), with **RFC 8484 DoH + true TLS 1.3 ECH (RFC 8446 + RFC 9180 HPKE + RFC 9849)** enabled by default (including automatic 1-shot `retry_configs` retry and ClientHello TCP fragmentation fallback when no ECH record is published), shipping dual ESM + CommonJS exports with full `.d.ts` type definitions.

```bash
# Install in a project
npm install neruton

# Or install globally for the CLI
npm install -g neruton
```

**ESM / TypeScript API**

```ts
import { connect, forward, http, DohError } from 'neruton';

const tunnel = await connect({
  url: 'http://127.0.0.1:3000',
  server: 'https://neruton.moer.eu.org', // optional; reads NERUTON_SERVER / config.toml
  token: process.env.NERUTON_TOKEN,      // optional; reads NERUTON_TOKEN / config.toml
  subdomain: 'my-app',                   // optional; server assigns UUID v4 if omitted
  doh: 'auto',                           // optional: 'auto' | 'strict' | 'off' | boolean | string[]
  sniMode: 'auto',                       // optional: 'auto' | 'ech' | 'fragment' | 'none' | 'plain'
  // sni: 'moer.eu.org',                 // optional custom SNI (cert still checked vs real host)
  // echConfig: '...',                   // optional base64 ECHConfigList (overrides DoH HTTPS record)
  onWarning: (msg) => console.warn(msg),
});

console.log('Public URL :', tunnel.publicUrl);
console.log('Preview URL:', tunnel.previewUrl);
console.log('Path URL   :', tunnel.pathUrl);
console.log('Prefix     :', tunnel.prefix);
console.log('Transport  :', tunnel.transportInfo?.summary);

tunnel.on('request', ({ method, path, status, durationMs }) => {
  console.log(`${status} ${method} ${path} (${durationMs}ms)`);
});

tunnel.on('reconnecting', ({ attempt, delayMs, reason }) => {
  console.warn(`Reconnect #${attempt} in ${delayMs}ms (${reason})`);
});

tunnel.on('warning', (message) => {
  console.warn(`Warning: ${message}`);
});

// Also supports `await using tunnel = await forward(3000)` via Symbol.asyncDispose
await tunnel.close();
```

**CommonJS API**

```js
const { connect, forward, http, loadConfig, saveConfig, configPath } = require('neruton');

async function main() {
  const tunnel = await forward(3000, {
    server: 'https://neruton.moer.eu.org',
    token: 'ntk_your_token_here',
    doh: 'strict',
    sniMode: 'ech',
  });
  console.log('Online at', tunnel.publicUrl, '|', tunnel.transportInfo?.summary);
  await tunnel.close();
}

main();
```

**CLI & Shared Config (`~/.config/neruton/config.toml`)**

The Node.js SDK shares `~/.config/neruton/config.toml` (mode `0600` on POSIX) and `NERUTON_SERVER`, `NERUTON_TOKEN` (plus `NERUTON_AUTH_TOKEN`), `NERUTON_DOH`, `NERUTON_SNI_MODE`, `NERUTON_SNI`, and `NERUTON_ECH_CONFIG` with the Rust CLI, and exports `configPath()`, `loadConfig()`, `saveConfig({ server, token, doh, sniMode, sni, echConfig })`, `resolveConnectionSettings()`, and `DohError`:

```bash
neruton config set --server https://neruton.moer.eu.org --token ntk_your_token_here --doh auto --sni-mode auto
neruton config show
neruton config path

neruton http 3000
neruton http 3000 -s my-app --doh strict --sni-mode ech
neruton tunnel --url http://127.0.0.1:3000 --subdomain my-app --no-doh --sni-mode plain
neruton version
```

### Server Deployment (Docker Compose + `cloudflared`)

1. Clone the repository and create `.env` from `.env.example`:
   ```bash
   git clone https://github.com/kaecho/neruton.git
   cd neruton
   cp .env.example .env
   ```
2. Create a remote-managed Cloudflare Tunnel and configure ingress rules pointing to `http://neruton-server:8080`:
   ```json
   {
     "config": {
       "ingress": [
         { "hostname": "neruton.moer.eu.org", "service": "http://neruton-server:8080" },
         { "hostname": "*.moer.eu.org", "service": "http://neruton-server:8080" },
         { "service": "http_status:404" }
       ]
     }
   }
   ```
3. Point proxied `CNAME` DNS records for `neruton.moer.eu.org` and `*.moer.eu.org` to `<tunnel-id>.cfargotunnel.com`.
4. Put your `CLOUDFLARED_TUNNEL_TOKEN` (and any optional auth bootstrap settings) into `.env`, then pull the prebuilt multi-arch (`amd64`/`arm64`) GHCR images (`ghcr.io/kaecho/neruton-server` & `ghcr.io/kaecho/neruton-web`) and start the stack without compiling on the server:
   ```bash
   docker compose pull && docker compose up -d
   ```
   `neruton-server` mounts the named Docker volume `neruton-data` at `/data` (`NERUTON_DATA_DIR=/data`) to persist `/data/state.json` across restarts and image upgrades.
5. **Local source-build verification without Cloudflare** (builds locally, binds `127.0.0.1:8080` only, and keeps the `/data` volume + production auth defaults):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.local.yml up --build
   ```

### Environment Variables

**Server environment variables** (for client variables `NERUTON_SERVER`, `NERUTON_TOKEN`, `NERUTON_DOH`, `NERUTON_SNI_MODE`, `NERUTON_SNI`, and `NERUTON_ECH_CONFIG`, see [Stealth Transport: Default DoH & Hidden SNI](#stealth-transport-default-doh--hidden-sni) above):

| Variable | Default | Description |
| --- | --- | --- |
| `NERUTON_IMAGE_TAG` | `latest` | GHCR image tag (`latest`, `v0.4.0`, etc.) |
| `NERUTON_BASE_DOMAIN` | `moer.eu.org` | Wildcard base domain (`<prefix>.<NERUTON_BASE_DOMAIN>`) |
| `NERUTON_PANEL_HOST` | `neruton.moer.eu.org` | Dashboard, Management API, and WSS tunnel hostname |
| `NERUTON_PUBLIC_SCHEME` | `https` | Public URL scheme (`https`/`http`); enables `Secure` on session cookies when `https` |
| `NERUTON_DATA_DIR` | `/data` (container) / `./data` (binary) | Persistent state directory containing `state.json` |
| `NERUTON_REQUIRE_AUTH` | `true` | Initial value for tunnel token enforcement (live-toggleable in Web `/settings`) |
| `NERUTON_ADMIN_USER` | `admin` | Admin username for unattended initial bootstrap |
| `NERUTON_ADMIN_PASSWORD` | *(empty)* | Optional initial admin password (>= 8 chars); leave empty for interactive Web UI setup |
| `NERUTON_SESSION_SECRET` | *(empty)* | Optional HMAC-SHA256 key for `neruton_session` cookies (auto-generated and persisted if unset) |
| `NERUTON_AUTH_TOKEN` | *(empty)* | Optional legacy/master Bearer token accepted alongside per-user `ntk_...` tokens |
| `CLOUDFLARED_TUNNEL_TOKEN` | *(required)* | Cloudflare Tunnel token for zero-host-port production ingress |

### Server HTTP & API Endpoints

- **Public & Auth**:
  - `GET /_neruton/health` — JSON health check (used by container healthcheck)
  - `GET /_neruton/tunnel` — WebSocket upgrade for Yamux tunnel registration & multiplexing
  - `GET /_neruton/api/auth/status` — Setup state, authentication status, and domain metadata
  - `POST /_neruton/api/auth/setup` — First-run admin account & initial CLI token creation
  - `POST /_neruton/api/auth/login` / `POST /_neruton/api/auth/logout` — Session cookie login & sign-out
- **Authenticated Management API** (requires `neruton_session` cookie):
  - `GET /_neruton/api/auth/me` & `POST /_neruton/api/auth/password` — Current user profile & password update
  - `GET /_neruton/api/info` — Server version, auth mode, uptime, and counters
  - `GET /_neruton/api/tunnels`, `GET|DELETE /_neruton/api/tunnels/:prefix`, `GET /_neruton/api/tunnels/:prefix/logs` — Scoped tunnel inspection & disconnect
  - `GET|DELETE /_neruton/api/logs` — Request logs (clear is admin-only)
  - `GET /_neruton/api/events` — Scoped Server-Sent Events (`text/event-stream`) live updates
  - `GET|POST /_neruton/api/tokens`, `PATCH|DELETE /_neruton/api/tokens/:id` — Per-user tunnel token management
  - `GET|POST /_neruton/api/users`, `PATCH|DELETE /_neruton/api/users/:id` — User RBAC management (admin-only)
  - `GET|PATCH /_neruton/api/settings` — Tunnel auth policy, user quota, and reserved prefixes (`PATCH` is admin-only)
- **Web Proxy & Viewer**:
  - `ANY /t/:prefix/*` — Path-based tunnel proxy for direct iframe previewing
  - `GET /preview/:prefix` — Embedded browser-style tunnel viewer served by `neruton-web`

### Releasing a New Version

Tagging and pushing any `v*` tag automatically triggers [`.github/workflows/release.yml`](.github/workflows/release.yml) and [`.github/workflows/docker.yml`](.github/workflows/docker.yml), cross-builds all 5 targets + multi-arch GHCR images, generates `SHA256SUMS.txt`, and publishes a GitHub Release automatically marked as `latest`:

```bash
git tag v0.4.0
git push origin v0.4.0
```

### License

MIT
