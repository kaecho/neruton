# Neruton

> 轻量级自托管内网穿透工具、泛域名反向代理与免绑域名 Web 预览面板（受 `cloudflared` 启发，纯 Rust + Next.js 构建）。  
> Lightweight, self-hosted intranet tunnel, wildcard subdomain reverse proxy, and zero-extra-domain web viewer inspired by `cloudflared`.

[中文文档](#中文文档) · [English Documentation](#english-documentation) · [Latest Releases](https://github.com/kaecho/neruton/releases/latest)

---

## 中文文档

### 核心特性

- **单连接穿透 443 端口（WSS + Yamux）**：客户端通过一条出站 WebSocket (`wss://`) 连接接入服务端，内部采用 **Yamux** 多路复用并发 HTTP/1.1 与 WebSocket 流量，天然穿越 NAT、企业防火墙以及 Cloudflare 代理。
- **泛域名路由（Wildcard Subdomain）**：支持自动生成随机 UUID v4 前缀（如 `https://<uuid>.moer.eu.org`），也支持通过 `--subdomain test-test` 绑定自定义子域名（如 `https://test-test.moer.eu.org`）。
- **免额外域名 Web 直览（`/preview/<prefix>` 与 `/t/<prefix>/`）**：无需为每个内网服务额外配置域名，可直接在 Web 控制台的 `/preview/<prefix>` 嵌入式浏览器中预览和调试隧道内容；服务端自动通过 `/t/<prefix>/` 路径代理转发、放松 iframe 限制并注入 `<base>` 标签。
- **零公网暴露端口部署**：服务端 Docker Compose 栈内置 `cloudflared`，所有入站流量经 Cloudflare Tunnel 进入内部 Docker 网络 `neruton-net`，宿主机无需开放任何端口。
- **实时控制台与流量审计**：Next.js 管理面板支持实时 SSE 隧道状态监控、请求日志流、CLI 命令生成器与一键断开隧道。

### 架构概览

```text
+-------------------+       WSS + Yamux (:443)       +------------------+
| Local Service     | <--- neruton CLI ------------> | Cloudflare Edge  |
| (localhost:3000)  |      (outbound only)           | *.moer.eu.org    |
+-------------------+                                | neruton.moer...  |
                                                     +--------+---------+
                                                              | Cloudflare Tunnel
                                                              | (zero host ports)
                                                     +--------v---------+
                                                     | cloudflared      |
                                                     +--------+---------+
                                                              | neruton-net
                                                     +--------v---------+
                                                     | neruton-server   |
                                                     | :8080 (Rust)     |
                                                     +---+----------+---+
                                    Wildcard / /t/*  |              | Panel UI /*
                                     (Yamux stream)  |              v
                                                     |     +----------------+
                                                     |     | neruton-web    |
                                                     |     | :3000 (NextJS) |
                                                     |     +----------------+
```

- **泛域名访问**：`Host: <prefix>.moer.eu.org` -> `neruton-server` 通过 Yamux 流直接代理到对应客户端本地服务。
- **面板与路径预览**：`Host: neruton.moer.eu.org`
  - `/_neruton/tunnel`：客户端 WebSocket + Yamux 控制与数据通道
  - `/_neruton/health` & `/_neruton/api/*`：健康检查、管理 REST API 与 SSE 实时事件流
  - `/t/<prefix>/...`：免额外域名路径代理（自动重写相对跳转与 `<base href="/t/<prefix>/">`）
  - `/preview/<prefix>` & `/`：反向代理到 `neruton-web` Next.js 控制台与嵌入式预览器

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

1. **使用随机 UUID 前缀启动隧道（默认行为）**
   ```bash
   neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000
   ```
   启动后会分配唯一的随机 UUID 前缀，例如：
   - 泛域名地址：`https://<uuid>.moer.eu.org`
   - Web 预览面板：`https://neruton.moer.eu.org/preview/<uuid>`
   - 直接路径代理：`https://neruton.moer.eu.org/t/<uuid>/`

2. **指定自定义子域名前缀（`--subdomain` / `-s` / `--prefix`）**
   ```bash
   neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000 --subdomain test-test
   ```
   分配地址为 `https://test-test.moer.eu.org` 与 `https://neruton.moer.eu.org/preview/test-test`。

3. **快捷命令 `neruton http`**
   ```bash
   # 将本机 3000 端口映射到随机 UUID 隧道
   neruton http 3000

   # 将本机 8080 端口映射到自定义子域名 test-test
   neruton http 8080 -s test-test
   ```

4. **保存默认配置（`~/.config/neruton/config.toml`）**
   ```bash
   neruton config set --server https://neruton.moer.eu.org --token YOUR_AUTH_TOKEN
   neruton config show
   ```
   保存后运行 `neruton http 3000` 或 `neruton tunnel --url http://127.0.0.1:3000` 即可自动读取服务端地址与认证令牌。

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

3. **填入 Token 并启动服务**
   编辑 `.env`，填入 `CLOUDFLARED_TUNNEL_TOKEN`（以及可选的 `NERUTON_AUTH_TOKEN`），然后执行：
   ```bash
   docker compose up -d --build
   docker compose ps
   ```
   整个栈仅使用内部桥接网络 `neruton-net`，宿主机 **0 端口监听**。

4. **本地调试模式（无需 Cloudflare）**
   如需在本地验证，可使用附带的覆盖文件仅在 `127.0.0.1:8080` 暴露服务端并跳过 `cloudflared`：
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.local.yml up --build
   ```

### 环境变量说明

| 变量名 | 默认值 | 说明 |
| --- | --- | --- |
| `NERUTON_BASE_DOMAIN` | `moer.eu.org` | 泛域名根域（`<prefix>.<NERUTON_BASE_DOMAIN>`） |
| `NERUTON_PANEL_HOST` | `neruton.moer.eu.org` | Web 控制台与隧道 WSS 接入域名 |
| `NERUTON_PUBLIC_SCHEME` | `https` | 对外展示的协议方案（`https` 或 `http`） |
| `NERUTON_AUTH_TOKEN` | *(空)* | 可选 Bearer Token；为空时开放注册 |
| `CLOUDFLARED_TUNNEL_TOKEN` | *(必填)* | Cloudflare Tunnel Token（生产部署） |

---

## English Documentation

### Highlights

- **WSS + Yamux over Port 443**: `neruton` opens a single outbound WebSocket (`wss://`) connection and multiplexes concurrent HTTP/1.1 & WebSocket streams via **Yamux**, traversing NATs, strict corporate firewalls, and Cloudflare proxies effortlessly.
- **Wildcard Subdomain Routing**: Assigns an automatic lowercase UUID v4 subdomain by default (`https://<uuid>.moer.eu.org`) or a custom subdomain via `--subdomain test-test` (`https://test-test.moer.eu.org`).
- **No-Extra-Domain Web Viewer (`/preview/<prefix>` & `/t/<prefix>/`)**: Inspect tunneled web services directly inside the dashboard's embedded browser viewport at `/preview/<prefix>` without binding additional domains. `neruton-server` serves `/t/<prefix>/` with frame-header relaxation, relative redirect rewriting, and automatic HTML `<base>` injection.
- **Zero-Exposed-Port Deployment**: Production `docker-compose.yml` pairs `neruton-server` and `neruton-web` with an outbound `cloudflared` connector on an internal bridge network (`neruton-net`)—no host ports are opened.
- **Pure-Rust TLS (`rustls`) & Multi-Platform Releases**: No OpenSSL dependency; every `v*` git tag automatically builds Linux (`x86_64`, `aarch64`), macOS (`aarch64`, `x86_64`), and Windows (`x86_64`) binaries and publishes them to [GitHub Releases (`latest`)](https://github.com/kaecho/neruton/releases/latest).

### Architecture

```text
Local App (:3000) <--> neruton CLI ==[ WSS + Yamux (:443) ]==> Cloudflare Edge
                                                                      |
                                                             cloudflared (outbound)
                                                                      | (neruton-net)
                                                              neruton-server (:8080)
                                                             /                      \
                                       *.<base_domain> & /t/*                        /* (Panel & /preview/*)
                                          (Yamux tunnel)                              neruton-web (:3000)
```

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
# 1. Start a tunnel with an auto-generated UUID v4 prefix
neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000

# 2. Start a tunnel with a custom subdomain (test-test.moer.eu.org)
neruton tunnel --server https://neruton.moer.eu.org --url http://127.0.0.1:3000 --subdomain test-test

# 3. Shorthand for local HTTP ports
neruton http 3000
neruton http 8080 -s test-test

# 4. Persist default server & optional auth token (~/.config/neruton/config.toml)
neruton config set --server https://neruton.moer.eu.org --token <YOUR_TOKEN>
neruton config show
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
4. Put your `CLOUDFLARED_TUNNEL_TOKEN` (and optional `NERUTON_AUTH_TOKEN`) into `.env` and start the stack:
   ```bash
   docker compose up -d --build
   ```
5. **Local verification without Cloudflare** (binds `127.0.0.1:8080` only):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.local.yml up --build
   ```

### Server HTTP & API Endpoints

- `GET /_neruton/health` — JSON health check (used by container healthcheck)
- `GET /_neruton/tunnel` — WebSocket upgrade for Yamux tunnel registration & multiplexing
- `GET /_neruton/api/info` — Server version, domain config, uptime, and counters
- `GET /_neruton/api/tunnels` — Active tunnels list
- `GET /_neruton/api/tunnels/:prefix` / `DELETE /_neruton/api/tunnels/:prefix` — Inspect or disconnect a tunnel
- `GET /_neruton/api/logs` / `GET /_neruton/api/tunnels/:prefix/logs` — Recent request logs
- `GET /_neruton/api/events` — Server-Sent Events (`text/event-stream`) live updates
- `ANY /t/:prefix/*` — Path-based tunnel proxy for direct iframe previewing
- `GET /preview/:prefix` — Embedded browser-style tunnel viewer served by `neruton-web`

### Releasing a New Version

Tagging and pushing any `v*` tag automatically triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), cross-builds all 5 targets, generates `SHA256SUMS.txt`, and publishes a GitHub Release automatically marked as `latest`:

```bash
git tag v0.1.0
git push origin v0.1.0
```

### License

MIT
