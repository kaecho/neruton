# neruton (Python SDK & CLI)

Native pure-Python tunnel client & SDK for [Neruton](https://github.com/kaecho/neruton) — self-hosted intranet penetration, wildcard subdomain reverse proxy, and WebSocket tunneling over port 443 (`WSS + Yamux`).

- **100% pure Python** (built on `cryptography` + `websockets`, no Rust binary wrapper) implementing the exact Neruton control protocol, **Yamux v0** multiplexer byte-for-byte compatible with `neruton-server` (`yamux 0.13`), and **native RFC 9849 TLS 1.3 ECH (Encrypted Client Hello)**.
- **Default DNS-over-HTTPS (RFC 8484) + True TLS 1.3 ECH**: IP-based DoH (zero bootstrap DNS leak) discovers `HTTPS` (Type 65) `ECHConfigList` records automatically and establishes a real RFC 8446 + RFC 9180 HPKE + RFC 9849 ECH connection (with strict RFC 5280 X.509 verification and 1-shot `retry_configs` recovery), falling back to TLS ClientHello TCP fragmentation when a server does not publish ECH. Also supports `--sni-mode ech` (strict ECH), custom/omitted SNI with strict RFC 6125 verification, and works out of the box in Python 3.9–3.14 (including Google Colab & Kaggle).
- **Async & Sync Python APIs** with full PEP 561 type annotations (`py.typed`).
- **Drop-in CLI** (`neruton` and `python -m neruton`) sharing `~/.config/neruton/config.toml` (`0600`) and `NERUTON_*` environment variables with the Rust CLI.
- **Full HTTP/1.1 & WebSocket forwarding** with Host rewriting, chunked streaming, local HTTPS (`--no-tls-verify`), automatic reconnect with sticky prefix, and fail-fast on HTTP 401 auth errors.

## Installation

```bash
pip install neruton
```

Requires Python 3.9+.

## Quick Start — Python SDK

### Async API (`asyncio` / FastAPI / Starlette / aiohttp)

```python
import asyncio
import neruton

async def main() -> None:
    async with neruton.connect(
        url="http://127.0.0.1:3000",
        server="https://neruton.moer.eu.org",
        token="ntk_your_token_here",
        subdomain="my-app",  # optional; auto-assigns UUID v4 if omitted
    ) as tunnel:
        print("Public URL :", tunnel.public_url)
        print("Preview URL:", tunnel.preview_url)
        print("Path URL   :", tunnel.path_url)
        print("Prefix     :", tunnel.prefix)
        print("Transport  :", tunnel.transport_info)
        await tunnel.wait()

asyncio.run(main())
```

Shorthand helpers for local ports:

```python
async with neruton.forward(3000, subdomain="my-app") as tunnel:
    print(tunnel.public_url)

# Alias matching `neruton http 8080`:
tunnel = await neruton.http(8080)
try:
    print(tunnel.public_url)
finally:
    await tunnel.close()
```

### Sync API (Flask / Django / Scripts / Notebooks)

`neruton.open(...)` runs the tunnel's `asyncio` event loop on a dedicated daemon thread and shuts down cleanly when exiting the `with` block:

```python
import neruton

with neruton.open(5000, server="https://neruton.moer.eu.org", token="ntk_your_token_here") as tunnel:
    print("Tunnel live at:", tunnel.public_url)
    app.run(port=5000)
```

### DNS-over-HTTPS (DoH) & TLS 1.3 ECH (Encrypted Client Hello)

By default (`doh="auto"`, `sni_mode="auto"`), non-local `wss://` connections resolve the gateway hostname via **RFC 8484 binary DoH** against IP-based endpoints (`1.0.0.1`, `223.5.5.5`, `1.1.1.1`, `8.8.4.4`, racing the first two with fallback — zero bootstrap DNS leak). When an `ECHConfigList` is discovered via the DoH `HTTPS` (Type 65) record (or supplied via `ech_config` / `--ech-config`), Neruton performs **true TLS 1.3 ECH (RFC 8446 + RFC 9180 HPKE + RFC 9849)** over `cryptography>=42.0.0` with strict RFC 5280 X.509 certificate verification and automatic 1-shot `retry_configs` retry — encrypting the real SNI so observers only see the outer `public_name` (e.g. `cloudflare-ech.com`). If no ECH record is available in `auto` mode, Neruton falls back to splitting the initial **TLS ClientHello across multiple TCP segments**. Local targets (`ws://`, `localhost`, `*.localhost`, `*.local`, and IP literals) automatically skip DoH and SNI hiding.

```python
# Strict DoH + strict TLS 1.3 ECH (fail fast if ECH is unavailable or rejected)
async with neruton.connect(3000, doh="strict", sni_mode="ech") as tunnel:
    print(tunnel.transport_info)  # DoH + ECH (outer: cloudflare-ech.com) | ... | TLSv1.3
    print(tunnel.transport_info.ech_status, tunnel.transport_info.outer_sni)

# Provide an explicit base64 ECHConfigList (e.g. from --ech-config / NERUTON_ECH_CONFIG)
async with neruton.connect(3000, sni_mode="ech", ech_config="AEX+DQ...") as tunnel:
    print(tunnel.transport_info)

# Custom DoH endpoint(s) and custom/omitted SNI (cert is still verified against real server host)
async with neruton.connect(
    3000,
    doh=["https://1.0.0.1/dns-query", "https://223.5.5.5/dns-query"],
    sni_mode="none",  # or sni="example-front.example"
) as tunnel:
    ...

# Disable DoH and SNI hiding
async with neruton.connect(3000, doh=False, sni_mode="plain") as tunnel:
    ...
```

### Config Helpers

```python
import neruton

print(neruton.config_path())  # ~/.config/neruton/config.toml
neruton.save_config(
    server="https://neruton.moer.eu.org",
    token="ntk_your_token_here",
    doh="auto",
    sni_mode="auto",
)
cfg = neruton.load_config()
```

## Quick Start — CLI

```bash
# Save default server, token, and stealth transport preferences (writes mode 0600 config.toml)
neruton config set --server https://neruton.moer.eu.org --token ntk_your_token_here --doh auto --sni-mode auto
neruton config show
neruton config path

# Forward a local port with default DoH + TLS 1.3 ECH (auto-fallback to ClientHello fragmentation)
neruton http 3000

# Override DoH / SNI options per invocation (CLI flags > NERUTON_* env > config.toml > defaults)
neruton http 8080 -s my-app --doh strict --sni-mode ech
neruton http 8080 -s my-app --doh strict --sni-mode fragment
neruton tunnel --url http://127.0.0.1:3000 --no-doh --sni-mode plain
neruton http 3000 --sni-mode none
neruton http 3000 --sni moer.eu.org

# Or invoke as a Python module
python -m neruton http 3000
python -m neruton version
```

Environment variables: `NERUTON_SERVER`, `NERUTON_TOKEN`, `NERUTON_DOH`, `NERUTON_SNI_MODE`, `NERUTON_SNI`, `NERUTON_ECH_CONFIG`.

## License

MIT
