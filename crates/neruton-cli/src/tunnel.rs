use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use neruton_proto::{
    build_tunnel_ws_url, normalize_target_url, validate_prefix, RegisterRequest, RegisterResponse,
    WsByteStream, YamuxServer, VERSION,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

use crate::forwarder::{handle_yamux_stream, HostHeaderMode, TargetConfig};
use crate::tls::{build_rustls_config, build_ws_connector};
use crate::ui;

pub struct TunnelOptions {
    pub server: String,
    pub target_url: String,
    pub subdomain: Option<String>,
    pub token: Option<String>,
    pub no_tls_verify: bool,
    pub host_header: Option<String>,
}

enum SessionExit {
    Shutdown,
    Fatal(String),
    Disconnected(String),
}

pub async fn run_tunnel_loop(opts: TunnelOptions) -> Result<()> {
    let target_url = normalize_target_url(&opts.target_url).map_err(|e| anyhow::anyhow!(e))?;
    let ws_url = build_tunnel_ws_url(&opts.server)
        .with_context(|| format!("invalid server URL '{}'", opts.server))?;

    let initial_prefix = match opts
        .subdomain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(validate_prefix(raw).map_err(|e| anyhow::anyhow!(e))?),
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
            ws_url.as_str(),
            opts.token.as_deref(),
            opts.no_tls_verify,
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
                ui::log_error(&reason);
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

async fn run_single_session(
    ws_url: &str,
    token: Option<&str>,
    no_tls_verify: bool,
    sticky_prefix: &mut Option<String>,
    target_cfg: Arc<TargetConfig>,
    ever_connected: &mut bool,
) -> SessionExit {
    let mut ws_req = match ws_url.into_client_request() {
        Ok(r) => r,
        Err(e) => return SessionExit::Fatal(format!("invalid WebSocket request: {e}")),
    };

    if let Some(tok) = token.map(str::trim).filter(|s| !s.is_empty()) {
        if let Ok(hv) = HeaderValue::from_str(&format!("Bearer {tok}")) {
            ws_req.headers_mut().insert("Authorization", hv);
        }
    }

    let connector = build_ws_connector(no_tls_verify);
    let connect_fut =
        tokio_tungstenite::connect_async_tls_with_config(ws_req, None, false, Some(connector));

    let (mut ws_stream, _http_resp) = tokio::select! {
        res = connect_fut => match res {
            Ok(pair) => pair,
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) if resp.status().as_u16() == 401 => {
                return SessionExit::Fatal(
                    "Authentication failed (401 Unauthorized). Provide a valid --token or NERUTON_TOKEN."
                        .to_string(),
                );
            }
            Err(e) => {
                return SessionExit::Disconnected(format!("connect failed: {e}"));
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
        if !*ever_connected {
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
