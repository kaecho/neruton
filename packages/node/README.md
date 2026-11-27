# neruton

Native pure-Node.js / TypeScript client SDK and CLI for [Neruton](https://github.com/kaecho/neruton) — a self-hosted intranet tunnel, wildcard subdomain reverse proxy, and zero-extra-domain web preview gateway.

- **Pure TypeScript / Node.js**: Full native Yamux v0 multiplexer over WebSocket binary frames (`yamux 0.13` wire-compatible), pure-TS RFC 8446 TLS 1.3 + RFC 9180 HPKE + RFC 9849 ECH using only built-in `node:crypto` + `node:tls`, zero native binaries, single runtime dependency (`ws`).
- **Default DoH + True TLS 1.3 ECH**: Built-in RFC 8484 DNS-over-HTTPS over IP-based endpoints (zero bootstrap DNS leak) paired with **true cryptographic TLS 1.3 Encrypted Client Hello (ECH)** by default (with automatic RFC 9849 1-shot `retry_configs` recovery and strict X.509 verification), falling back automatically to ClientHello TCP fragmentation when no ECHConfigList is published.
- **Dual ESM & CJS**: Works with both `import { connect } from 'neruton'` and `const neruton = require('neruton')`, complete with `.d.ts` type definitions.
- **HTTP/1.1 & WebSocket forwarding**: Streaming/chunked bodies, Host header rewriting/preservation, HTTPS local targets, and full bidirectional WebSocket upgrades.
- **CLI compatible with Rust `neruton`**: Shares `~/.config/neruton/config.toml` (`0600` permissions) and `NERUTON_*` environment variables.

## Installation

```bash
npm install neruton
```

Or install globally for the CLI:

```bash
npm install -g neruton
```

Requires **Node.js >= 18**.

## DNS-over-HTTPS (DoH) & Hidden SNI

By default (`doh: 'auto'`, `sniMode: 'auto'`), Neruton resolves remote gateway hostnames via **RFC 8484 binary POST (`application/dns-message`)** against IP-based DoH endpoints (avoiding plaintext DNS and bootstrap DNS leaks):

- Default endpoints: `https://1.0.0.1/dns-query`, `https://223.5.5.5/dns-query`, `https://1.1.1.1/dns-query`, `https://8.8.4.4/dns-query` (races the first two with a ~3s timeout and falls back across remaining endpoints).
- Automatically skipped for `localhost`, `*.localhost`, `*.local`, and IPv4/IPv6 literals.
- In `'auto'` mode, falls back to system DNS with a warning if all DoH endpoints are unreachable; use `doh: 'strict'` (or explicit custom `https://...` DoH URLs, which also fail closed) to prevent plaintext DNS fallback, or `doh: 'off'` / `--no-doh` to use system DNS.

For `wss://` connections to non-local hostnames:

- **`auto` (default)**: Uses **true TLS 1.3 ECH (RFC 8446 + RFC 9180 HPKE + RFC 9849)** whenever an `ECHConfigList` is available from `--ech-config` or a DoH `HTTPS` (Type 65) record (for example, `DoH + ECH (outer: cloudflare-ech.com)` with automatic RFC 9849 1-shot `retry_configs` retry and strict X.509 chain & hostname verification). If no `ECHConfigList` is available, automatically falls back to ClientHello TCP fragmentation.
- **`ech`**: Strictly requires **true TLS 1.3 ECH**; fails fast without retrying if no compatible `ECHConfigList` is available or if the server still rejects ECH after the RFC 9849 1-shot `retry_configs` retry (never sends application data or Bearer tokens over an unencrypted SNI connection).
- **`fragment`**: Splits the initial TLS ClientHello record (`0x16 0x03 ...`) across multiple flushed TCP segments (`TCP_NODELAY`) before switching to transparent pass-through, defeating stateless single-packet SNI inspection while keeping full TLS 1.3 certificate verification.
- **`none`**: Omits TLS SNI (`servername: ''`) while strictly validating the server certificate against the real target hostname (best for self-hosted servers that do not require SNI; note that Cloudflare-fronted endpoints reject omitted SNI).
- **`--sni <HOST>` / `sni`**: Sends a custom SNI hostname while strictly verifying the server certificate against the real target hostname. Combined with `sniMode: 'auto'`, also enables ClientHello fragmentation.
- **`plain`**: Standard TLS SNI without ECH or fragmentation.

### Configuration Precedence

Explicit option / CLI flag > Environment variable > `~/.config/neruton/config.toml` > Defaults (`doh = "auto"`, `sni_mode = "auto"`).

| Setting | CLI Flag | Environment Variable | `config.toml` Key | Default |
| --- | --- | --- | --- | --- |
| Server | `--server <URL>` | `NERUTON_SERVER` | `server` | `https://neruton.moer.eu.org` |
| Token | `--token <TOKEN>` | `NERUTON_TOKEN` / `NERUTON_AUTH_TOKEN` | `token` | — |
| DoH | `--doh <MODE_OR_URLS>` / `--no-doh` | `NERUTON_DOH` | `doh` | `"auto"` |
| SNI Mode | `--sni-mode <auto\|ech\|fragment\|none\|plain>` | `NERUTON_SNI_MODE` | `sni_mode` | `"auto"` |
| Custom SNI | `--sni <HOST>` | `NERUTON_SNI` | `sni` | — |
| ECH Config | `--ech-config <BASE64>` | `NERUTON_ECH_CONFIG` | `ech_config` | — |

## Programmatic Usage

### ESM / TypeScript

```ts
import { connect, forward, http } from 'neruton';

const tunnel = await connect({
  url: 'http://127.0.0.1:3000',
  server: 'https://neruton.moer.eu.org', // optional: reads NERUTON_SERVER / config.toml
  token: process.env.NERUTON_TOKEN,      // optional: reads NERUTON_TOKEN / config.toml
  subdomain: 'my-app',                   // optional: server assigns UUID v4 if omitted
  doh: 'auto',                           // 'auto' | 'strict' | 'off' | boolean | URL(s)
  sniMode: 'auto',                       // 'auto' | 'fragment' | 'none' | 'plain' | 'ech'
  // sni: 'alt.example.com',             // optional custom SNI (cert still checked vs real host)
});

console.log('Wildcard URL:', tunnel.publicUrl);
console.log('Web Preview: ', tunnel.previewUrl);
console.log('Path URL:    ', tunnel.pathUrl);
console.log('Prefix:      ', tunnel.prefix);
console.log('Transport:   ', tunnel.transportInfo?.summary);

tunnel.on('request', ({ method, path, status, durationMs }) => {
  console.log(`${status} ${method} ${path} (${durationMs}ms)`);
});

tunnel.on('reconnecting', ({ attempt, delayMs, reason }) => {
  console.warn(`Reconnect #${attempt} in ${delayMs}ms (${reason})`);
});

// Close when done
await tunnel.close();
```

### Shorthand Helpers & `await using`

```ts
import { forward, http } from 'neruton';

// Shorthand for exposing a local port:
await using tunnel = await forward(3000, { subdomain: 'demo' });
console.log(tunnel.publicUrl);
// Automatically closed when leaving scope via Symbol.asyncDispose

// Alias matching `neruton http 3000`:
const t = await http(3000);
await t.close();
```

### CommonJS

```js
const { connect, forward, loadConfig, saveConfig, configPath } = require('neruton');

async function main() {
  const tunnel = await forward(3000, {
    server: 'https://neruton.moer.eu.org',
    token: 'ntk_your_token',
  });
  console.log('Online at', tunnel.publicUrl);
  console.log('Transport:', tunnel.transportInfo?.summary);
  await tunnel.close();
}

main();
```

### Configuration Helpers

```ts
import { configPath, loadConfig, saveConfig } from 'neruton';

console.log('Config file:', configPath());
saveConfig({
  server: 'https://neruton.moer.eu.org',
  token: 'ntk_your_token',
  doh: 'auto',
  sniMode: 'auto',
});
const cfg = loadConfig();
```

## CLI Usage

```bash
# Save defaults to ~/.config/neruton/config.toml (mode 0600)
neruton config set --server https://neruton.moer.eu.org --token ntk_your_token --doh auto --sni-mode auto
neruton config show
neruton config path

# Start a tunnel (shorthand — uses DoH + true TLS 1.3 ECH by default when available, else ClientHello fragmentation)
neruton http 3000
neruton http 3000 --subdomain my-app

# Explicit stealth options
neruton tunnel --url http://127.0.0.1:3000 --doh strict --sni-mode ech
neruton tunnel --url http://127.0.0.1:3000 --doh strict --sni-mode fragment
neruton http 3000 --no-doh --sni-mode plain
neruton http 3000 --doh https://1.0.0.1/dns-query,https://223.5.5.5/dns-query --sni moer.eu.org

# Print version
neruton version
```

## API Reference

### `connect(options: ConnectOptions): Promise<Tunnel>`

(`TunnelOptions` is exported as an alias of `ConnectOptions`.)

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `url` | `string \| number` | required | Local target port or URL (`3000`, `localhost:3000`, `http://127.0.0.1:3000`, `https://localhost:8443`) |
| `server` | `string` | `NERUTON_SERVER` -> `config.toml` -> `https://neruton.moer.eu.org` | Neruton gateway server URL |
| `token` | `string` | `NERUTON_TOKEN` -> `NERUTON_AUTH_TOKEN` -> `config.toml` | Bearer tunnel token |
| `subdomain` / `prefix` | `string` | auto UUID v4 | Custom subdomain prefix |
| `noTlsVerify` | `boolean` | `false` | Disable TLS certificate verification |
| `hostHeader` | `string` | `'rewrite'` | `'rewrite'`, `'preserve'`, or custom Host value |
| `doh` | `boolean \| string \| string[]` | `NERUTON_DOH` -> `config.toml` -> `'auto'` | DoH mode (`'auto'`, `'strict'`, `'off'`, `boolean`) or RFC 8484 endpoint URL(s) |
| `sniMode` | `'auto' \| 'ech' \| 'fragment' \| 'none' \| 'plain'` | `NERUTON_SNI_MODE` -> `config.toml` -> `'auto'` | TLS SNI hiding mode |
| `sni` | `string` | `NERUTON_SNI` -> `config.toml` | Custom TLS SNI hostname (cert strictly validated against real host) |
| `echConfig` | `string` | `NERUTON_ECH_CONFIG` -> `config.toml` | Base64-encoded `ECHConfigList` overriding DoH `HTTPS` records for TLS 1.3 ECH |
| `configPath` | `string` | `~/.config/neruton/config.toml` | Custom path to `config.toml` |
| `reconnect` | `boolean` | `true` | Auto-reconnect with exponential backoff (1s -> 30s) |
| `signal` | `AbortSignal` | — | Cancel connection or close tunnel |
| `onWarning` | `(message: string) => void` | — | Callback for non-fatal warnings (e.g. DoH fallback to system DNS) |

### `Tunnel` Instance

- **Properties**: `publicUrl`, `previewUrl`, `pathUrl`, `dashboardUrl`, `prefix`, `tunnelId`, `targetUrl`, `ownerUsername`, `tokenName`, `connected`, `closed`, `transportInfo`
- **Methods**: `close(): Promise<void>`, `wait(): Promise<void>`, `[Symbol.asyncDispose](): Promise<void>`
- **Events**: `'connected'`, `'reconnecting'`, `'disconnected'`, `'error'`, `'request'`, `'warning'`

## License

MIT
