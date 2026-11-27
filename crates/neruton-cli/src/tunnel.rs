use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use neruton_proto::{
    build_tunnel_ws_url, normalize_target_url, validate_prefix, ErrorResponse, RegisterRequest,
    RegisterResponse, WsByteStream, YamuxServer, VERSION,
};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tracing::debug;
use url::Url;

use crate::doh::{resolve_host, strip_ipv6_brackets, DohConfig};
use crate::forwarder::{handle_yamux_stream, HostHeaderMode, TargetConfig};
use crate::tls::{
    build_rustls_config, connect_stealth_tls, StealthTlsOptions, TlsConnectError, TunnelStream,
};
use crate::ui;

const PLAIN_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct TunnelOptions {
    pub server: String,
    pub target_url: String,
    pub subdomain: Option<String>,
    pub token: Option<String>,
    pub no_tls_verify: bool,
    pub host_header: Option<String>,
    pub doh: DohConfig,
    pub tls: StealthTlsOptions,
}

enum SessionExit {
    Shutdown,
    Fatal(String),
    Disconnected(String),
}

pub async fn run_tunnel_loop(opts: TunnelOptions) -> Result<()> {
    let target_url = normalize_target_url(&opts.target_url).map_err(|e| anyhow!(e))?;
    let ws_url = build_tunnel_ws_url(&opts.server)
        .with_context(|| format!("invalid server URL '{}'", opts.server))?;

    let initial_prefix = match opts
        .subdomain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(validate_prefix(raw).map_err(|e| anyhow!(e))?),
        None => None,
    };

    let tls_config = build_rustls_config(opts.no_tls_verify);
    let target_cfg = Arc::new(TargetConfig::new(
        target_url.clone(),
        HostHeaderMode::from_option(opts.host_header),
        tls_config,
    )?);

    let mut sticky_prefix = initial_prefix;
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);
    let mut ever_connected = false;

    loop {
        ui::log_info(&format!(
            "Connecting to {} (target: {})...",
            ws_url, target_url
        ));

        let connected_at = Instant::now();
        let outcome = run_single_session(
            &ws_url,
            opts.token.as_deref(),
            &opts.doh,
            &opts.tls,
            &mut sticky_prefix,
            target_cfg.clone(),
            &mut ever_connected,
        )
        .await;

        match outcome {
            SessionExit::Shutdown => {
                ui::log_info("Tunnel shut down cleanly.");
                return Ok(());
            }
            SessionExit::Fatal(reason) => {
                bail!(reason);
            }
            SessionExit::Disconnected(reason) => {
                if connected_at.elapsed() >= Duration::from_secs(10) {
                    backoff = Duration::from_secs(1);
                }
                ui::log_warn(&format!(
                    "Disconnected ({reason}). Reconnecting in {}s...",
                    backoff.as_secs()
                ));

                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = tokio::signal::ctrl_c() => {
                        ui::log_info("Cancelled during reconnect backoff.");
                        return Ok(());
                    }
                }
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

fn format_401_error(body: Option<&[u8]>, had_token: bool) -> String {
    let server_msg = body
        .and_then(|bytes| serde_json::from_slice::<ErrorResponse>(bytes).ok())
        .map(|err| err.error)
        .filter(|s| !s.trim().is_empty());

    let detail = server_msg.unwrap_or_else(|| {
        if had_token {
            "Invalid, disabled, or revoked tunnel token.".to_string()
        } else {
            "Authentication token required by this Neruton server.".to_string()
        }
    });

    if had_token {
        format!(
            "Authentication failed (401 Unauthorized): {detail}\n  Verify or regenerate your token in the Neruton web panel, then run:\n    neruton config set --token <TOKEN>"
        )
    } else {
        format!(
            "Authentication failed (401 Unauthorized): {detail}\n  Create a token in the Neruton web panel, then run:\n    neruton config set --token <TOKEN>\n  Or pass --token <TOKEN> (or set NERUTON_TOKEN)."
        )
    }
}

fn is_non_retryable_rejection(err_msg: &str) -> bool {
    let lower = err_msg.to_ascii_lowercase();
    lower.contains("not permitted")
        || lower.contains("restricted to specific prefixes")
        || lower.contains("is reserved")
        || lower.contains("must match dns label")
        || lower.contains("tunnel limit reached")
}

/// Open TCP + optional stealth TLS stream with DoH resolution and multi-IP failover.
async fn establish_tunnel_transport(
    ws_url: &Url,
    doh: &DohConfig,
    tls_opts: &StealthTlsOptions,
) -> std::result::Result<(TunnelStream, String), TlsConnectError> {
    let is_tls = match ws_url.scheme() {
        "wss" => true,
        "ws" => false,
        other => {
            return Err(TlsConnectError::Fatal(format!(
                "unsupported WebSocket scheme '{other}'"
            )))
        }
    };

    let host_raw = ws_url
        .host_str()
        .ok_or_else(|| TlsConnectError::Fatal("server URL is missing a host".to_string()))?;
    let real_host = strip_ipv6_brackets(host_raw);
    let port = ws_url
        .port_or_known_default()
        .unwrap_or(if is_tls { 443 } else { 80 });

    let resolved = resolve_host(doh, real_host, port)
        .await
        .map_err(|e| TlsConnectError::Retryable(format!("DNS resolution failed: {e}")))?;

    let mut last_err: Option<String> = None;

    for addr in &resolved.addrs {
        if !is_tls {
            match tokio::time::timeout(PLAIN_TCP_CONNECT_TIMEOUT, TcpStream::connect(*addr)).await {
                Ok(Ok(tcp)) => {
                    let _ = tcp.set_nodelay(true);
                    let label = format!("{} + ws (plaintext)", resolved.source.short_label());
                    return Ok((TunnelStream::Plain(tcp), format!("{addr} [{label}]")));
                }
                Ok(Err(e)) => {
                    last_err = Some(format!("TCP connect to {addr} failed: {e}"));
                }
                Err(_) => {
                    last_err = Some(format!("TCP connect to {addr} timed out"));
                }
            }
            continue;
        }

        match connect_stealth_tls(
            *addr,
            real_host,
            tls_opts,
            resolved.ech_config_list.as_deref(),
        )
        .await
        {
            Ok(connected) => {
                debug!(
                    addr = %addr,
                    host = real_host,
                    ech_status = ?connected.ech_status,
                    mode = %connected.mode_label,
                    "stealth TLS handshake succeeded"
                );
                let label = format!(
                    "{} + {}",
                    resolved.source.short_label(),
                    connected.mode_label
                );
                return Ok((connected.stream, format!("{addr} [{label}]")));
            }
            Err(TlsConnectError::Fatal(msg)) => return Err(TlsConnectError::Fatal(msg)),
            Err(TlsConnectError::Retryable(msg)) => {
                last_err = Some(msg);
            }
        }
    }

    Err(TlsConnectError::Retryable(last_err.unwrap_or_else(|| {
        format!("failed to connect to any resolved address for '{real_host}:{port}'")
    })))
}

async fn run_single_session(
    ws_url: &Url,
    token: Option<&str>,
    doh: &DohConfig,
    tls_opts: &StealthTlsOptions,
    sticky_prefix: &mut Option<String>,
    target_cfg: Arc<TargetConfig>,
    ever_connected: &mut bool,
) -> SessionExit {
    let mut ws_req = match ws_url.as_str().into_client_request() {
        Ok(r) => r,
        Err(e) => return SessionExit::Fatal(format!("invalid WebSocket request: {e}")),
    };

    let normalized_token = token.map(str::trim).filter(|s| !s.is_empty());
    if let Some(tok) = normalized_token {
        if let Ok(hv) = HeaderValue::from_str(&format!("Bearer {tok}")) {
            ws_req.headers_mut().insert("Authorization", hv);
        }
    }

    let (transport, transport_desc) = tokio::select! {
        res = establish_tunnel_transport(ws_url, doh, tls_opts) => match res {
            Ok(pair) => pair,
            Err(TlsConnectError::Fatal(reason)) => return SessionExit::Fatal(reason),
            Err(TlsConnectError::Retryable(reason)) => {
                return SessionExit::Disconnected(format!("connect failed: {reason}"));
            }
        },
        _ = tokio::signal::ctrl_c() => return SessionExit::Shutdown,
    };

    ui::log_info(&format!("Transport established: {transport_desc}"));

    let ws_fut = tokio_tungstenite::client_async_with_config(ws_req, transport, None);

    let (mut ws_stream, _http_resp) = tokio::select! {
        res = ws_fut => match res {
            Ok(pair) => pair,
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) if resp.status().as_u16() == 401 => {
                let body_bytes = resp.body().as_deref();
                return SessionExit::Fatal(format_401_error(body_bytes, normalized_token.is_some()));
            }
            Err(e) => {
                return SessionExit::Disconnected(format!("WebSocket upgrade failed: {e}"));
            }
        },
        _ = tokio::signal::ctrl_c() => return SessionExit::Shutdown,
    };

    let reg_req = RegisterRequest {
        prefix: sticky_prefix.clone(),
        target_url: target_cfg.url.to_string(),
        client_version: VERSION.to_string(),
        client_os: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
    };

    let reg_json = match serde_json::to_string(&reg_req) {
        Ok(j) => j,
        Err(e) => return SessionExit::Fatal(format!("serialization error: {e}")),
    };

    if let Err(e) = ws_stream.send(Message::Text(reg_json.into())).await {
        return SessionExit::Disconnected(format!("failed sending registration: {e}"));
    }

    let reg_resp = match tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(frame) = ws_stream.next().await {
            match frame {
                Ok(Message::Text(text)) => {
                    return serde_json::from_str::<RegisterResponse>(&text)
                        .map_err(|e| format!("invalid server response JSON: {e}"));
                }
                Ok(Message::Ping(p)) => {
                    let _ = ws_stream.send(Message::Pong(p)).await;
                }
                Ok(Message::Close(_)) => return Err("server closed connection".to_string()),
                Ok(_) => {}
                Err(e) => return Err(format!("read error: {e}")),
            }
        }
        Err("connection closed before registration reply".to_string())
    })
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return SessionExit::Disconnected(e),
        Err(_) => return SessionExit::Disconnected("registration timed out".to_string()),
    };

    if !reg_resp.ok {
        let err_msg = reg_resp
            .error
            .unwrap_or_else(|| "registration rejected by server".to_string());
        if !*ever_connected || is_non_retryable_rejection(&err_msg) {
            return SessionExit::Fatal(format!("Registration rejected: {err_msg}"));
        }
        return SessionExit::Disconnected(format!("re-registration rejected: {err_msg}"));
    }

    // Preserve the assigned prefix (including server-generated UUID) across future auto-reconnects.
    *sticky_prefix = Some(reg_resp.prefix.clone());
    *ever_connected = true;

    ui::print_banner(&reg_resp, target_cfg.url.as_str());

    let ws_io = WsByteStream::new(ws_stream);
    let mut yamux_server = YamuxServer::spawn(ws_io);

    loop {
        tokio::select! {
            maybe_stream = yamux_server.accept() => {
                match maybe_stream {
                    Some(stream) => {
                        let target = target_cfg.clone();
                        tokio::spawn(async move {
                            handle_yamux_stream(stream, target).await;
                        });
                    }
                    None => {
                        return SessionExit::Disconnected("tunnel stream closed by server".to_string());
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                yamux_server.close();
                let _ = tokio::time::timeout(Duration::from_secs(2), yamux_server.wait_closed()).await;
                return SessionExit::Shutdown;
            }
        }
    }
}
