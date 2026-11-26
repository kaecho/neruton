# Neruton

> 轻量级自托管内网穿透工具、泛域名反向代理与免绑域名 Web 预览面板（受 `cloudflared` 启发，纯 Rust + Next.js 构建）。  
> Lightweight, self-hosted intranet tunnel, wildcard subdomain reverse proxy, and zero-extra-domain web viewer inspired by `cloudflared`.

[中文文档](#中文文档) · [English Documentation](#english-documentation) · [Latest Releases](https://github.com/kaecho/neruton/releases/latest)

---

## 中文文档

### 核心特性（v0.2.0）

- **单连接穿透 443 端口（WSS + Yamux）**：客户端通过一条出站 WebSocket (`wss://`) 连接接入服务端，内部采用 **Yamux** 多路复用并发 HTTP/1.1 与 WebSocket 流量，天然穿越 NAT、企业防火墙以及 Cloudflare 代理。
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
   # 将本机 3000 端口映射到随机 UUID 隧道（自动使用已保存的 server 与 token）
   neruton http 3000

   # 将本机 8080 端口映射到自定义子域名 test-test
   neruton http 8080 -s test-test

   # 临时指定令牌连接
   neruton http 3000 --token ntk_your_token_here
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

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `NERUTON_IMAGE_TAG` | `latest` | GHCR 镜像标签（如 `latest`、`v0.2.0`） |
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

### Highlights (v0.2.0)

- **WSS + Yamux over Port 443**: `neruton` opens a single outbound WebSocket (`wss://`) connection and multiplexes concurrent HTTP/1.1 & WebSocket streams via **Yamux**, traversing NATs, strict corporate firewalls, and Cloudflare proxies effortlessly.
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
- **Pure-Rust TLS (`rustls`) & Multi-Platform Releases**: Zero OpenSSL/C dependencies; every `v*` git tag builds Linux (`x86_64`, `aarch64`), macOS (`aarch64`, `x86_64`), and Windows (`x86_64`) binaries and publishes them to [GitHub Releases (`latest`)](https://github.com/kaecho/neruton/releases/latest).

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

# 4. Shorthand for local HTTP ports (reuses saved server & token, or pass --token / NERUTON_TOKEN)
neruton http 3000
neruton http 8080 -s test-test
neruton http 3000 --token ntk_your_token_here
```

> With tunnel token authentication enabled by default, `neruton` exits cleanly with a clear error on `401` instead of looping reconnects if the token is missing, invalid, or revoked.

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

| Variable | Default | Description |
| --- | --- | --- |
| `NERUTON_IMAGE_TAG` | `latest` | GHCR image tag (`latest`, `v0.2.0`, etc.) |
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
git tag v0.2.0
git push origin v0.2.0
```

### License

MIT
