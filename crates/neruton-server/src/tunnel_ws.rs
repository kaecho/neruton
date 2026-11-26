use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Extension, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use bytes::Bytes;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use neruton_proto::ws_stream::{WsByteStream, WsFrame, WsFrameKind, WsPingTracker};
use neruton_proto::{
    generate_uuid_prefix, validate_prefix_with_extra_reserved, ErrorResponse, RegisterRequest,
    RegisterResponse, ServerEvent, YamuxClient,
};
use serde::Deserialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::state::{ActiveTunnel, AppState};

#[derive(Debug, Deserialize)]
pub struct TunnelQuery {
    pub token: Option<String>,
}

/// Bridge `axum::extract::ws::Message` onto `neruton_proto::WsFrame` so `WsByteStream`
/// adapts Axum WebSockets cleanly into Yamux binary transports.
struct AxumWsMessage(Message);

impl WsFrame for AxumWsMessage {
    fn binary(data: Bytes) -> Self {
        AxumWsMessage(Message::Binary(data))
    }

    fn ping(data: Bytes) -> Self {
        AxumWsMessage(Message::Ping(data))
    }

    fn into_kind(self) -> WsFrameKind {
        match self.0 {
            Message::Binary(b) => WsFrameKind::Binary(b),
            Message::Text(t) => WsFrameKind::Text(t.to_string()),
            Message::Ping(p) => WsFrameKind::Ping(p),
            Message::Pong(p) => WsFrameKind::Pong(p),
            Message::Close(_) => WsFrameKind::Close,
        }
    }
}

/// Wrapper translating Axum's `WebSocket` stream/sink items to `AxumWsMessage`.
struct AxumWsAdapter(WebSocket);

impl futures_util::Stream for AxumWsAdapter {
    type Item = Result<AxumWsMessage, axum::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0
            .poll_next_unpin(cx)
            .map(|opt| opt.map(|res| res.map(AxumWsMessage)))
    }
}

impl futures_util::Sink<AxumWsMessage> for AxumWsAdapter {
    type Error = axum::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_ready_unpin(cx)
    }

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: AxumWsMessage,
    ) -> Result<(), Self::Error> {
        self.0.start_send_unpin(item.0)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_flush_unpin(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.0.poll_close_unpin(cx)
    }
}

struct PrefixGuard {
    state: Arc<AppState>,
    prefix: String,
}

impl Drop for PrefixGuard {
    fn drop(&mut self) {
        self.state.reserved_prefixes.remove(&self.prefix);
    }
}

pub async fn ws_tunnel_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<TunnelQuery>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    if !state.is_authorized(&headers, query.token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized: invalid or missing auth token".to_string(),
            }),
        )
            .into_response();
    }

    let remote_addr = extract_remote_ip(&headers, connect_info.map(|Extension(c)| c.0));
    ws.on_upgrade(move |socket| handle_tunnel_socket(socket, state, remote_addr))
}

fn extract_remote_ip(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(cf_ip) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return cf_ip.to_string();
    }
    if let Some(xff) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return xff.to_string();
    }
    peer.map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn send_register_error(socket: &mut WebSocket, msg: impl Into<String>) {
    let resp = RegisterResponse::err(msg);
    if let Ok(json) = serde_json::to_string(&resp) {
        let _ = socket.send(Message::Text(json.into())).await;
    }
    let _ = socket.send(Message::Close(None)).await;
}

async fn handle_tunnel_socket(mut socket: WebSocket, state: Arc<AppState>, remote_addr: String) {
    // 1. Wait for RegisterRequest text frame (with 10s handshake timeout).
    let reg_req = match tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(frame) = socket.recv().await {
            match frame {
                Ok(Message::Text(text)) => {
                    return serde_json::from_str::<RegisterRequest>(&text)
                        .map_err(|e| format!("invalid registration JSON: {e}"));
                }
                Ok(Message::Ping(p)) => {
                    let _ = socket.send(Message::Pong(p)).await;
                }
                Ok(Message::Close(_)) => return Err("client closed before registration".into()),
                Ok(_) => return Err("expected JSON text registration frame".into()),
                Err(e) => return Err(format!("websocket read error: {e}")),
            }
        }
        Err("connection closed before registration".into())
    })
    .await
    {
        Ok(Ok(req)) => req,
        Ok(Err(err)) => {
            warn!(%remote_addr, error = %err, "tunnel handshake failed");
            send_register_error(&mut socket, err).await;
            return;
        }
        Err(_) => {
            warn!(%remote_addr, "tunnel handshake timed out");
            send_register_error(&mut socket, "registration handshake timed out").await;
            return;
        }
    };

    // 2. Validate or auto-generate prefix.
    let extra_reserved = state.config.panel_subdomain_label();
    let requested_prefix = reg_req
        .prefix
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let prefix = match requested_prefix {
        Some(raw) => match validate_prefix_with_extra_reserved(raw, extra_reserved.as_deref()) {
            Ok(valid) => valid,
            Err(err) => {
                send_register_error(&mut socket, err.to_string()).await;
                return;
            }
        },
        None => generate_uuid_prefix(),
    };

    // 3. Atomically reserve prefix (reject active duplicates).
    if !state.reserved_prefixes.insert(prefix.clone()) {
        send_register_error(
            &mut socket,
            format!("prefix '{prefix}' is already in use by an active tunnel"),
        )
        .await;
        return;
    }
    let _prefix_guard = PrefixGuard {
        state: state.clone(),
        prefix: prefix.clone(),
    };

    let tunnel_id = Uuid::new_v4().to_string();
    let public_url = state.config.public_url(&prefix);
    let path_url = state.config.path_url(&prefix);
    let preview_url = state.config.preview_url(&prefix);
    let dashboard_url = state.config.dashboard_url();

    let reg_resp = RegisterResponse {
        ok: true,
        tunnel_id: tunnel_id.clone(),
        prefix: prefix.clone(),
        public_url: public_url.clone(),
        path_url: path_url.clone(),
        preview_url: preview_url.clone(),
        dashboard_url,
        error: None,
    };

    let resp_json = match serde_json::to_string(&reg_resp) {
        Ok(j) => j,
        Err(e) => {
            warn!("failed to serialize RegisterResponse: {e}");
            return;
        }
    };

    if let Err(e) = socket.send(Message::Text(resp_json.into())).await {
        warn!(%prefix, error = %e, "failed to send RegisterResponse");
        return;
    }
    if let Err(e) = socket.flush().await {
        warn!(%prefix, error = %e, "failed to flush RegisterResponse");
        return;
    }

    // 4. Switch WebSocket to Yamux binary multiplexing with periodic WebSocket keepalive pings.
    let (ping_tx, ping_rx) = mpsc::channel::<Bytes>(8);
    let latency_ms = Arc::new(AtomicU64::new(0));
    let epoch = Instant::now();

    let ws_stream = WsByteStream::with_ping_tracker(
        AxumWsAdapter(socket),
        WsPingTracker {
            ping_rx,
            latency_ms: latency_ms.clone(),
            epoch,
        },
    );
    let (yamux_client, yamux_driver) = YamuxClient::spawn(ws_stream);

    let tunnel = Arc::new(ActiveTunnel::new(
        tunnel_id.clone(),
        prefix.clone(),
        public_url.clone(),
        path_url,
        preview_url,
        reg_req.target_url,
        reg_req.client_version,
        reg_req.client_os,
        remote_addr.clone(),
        Utc::now().to_rfc3339(),
        latency_ms,
        yamux_client,
    ));

    state.tunnels.insert(prefix.clone(), tunnel.clone());
    state.emit_event(ServerEvent::TunnelConnected {
        tunnel: tunnel.to_info(),
    });

    info!(
        %prefix,
        %tunnel_id,
        %remote_addr,
        %public_url,
        "tunnel connected"
    );

    // Periodic WS Ping task (initial probe after 200ms, then every 15s for keepalive & RTT).
    let ping_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            let now_us = epoch.elapsed().as_micros() as u64;
            if ping_tx
                .send(Bytes::copy_from_slice(&now_us.to_be_bytes()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    match yamux_driver.await {
        Ok(Ok(())) => debug!(%prefix, %tunnel_id, "tunnel yamux session closed cleanly"),
        Ok(Err(e)) => debug!(%prefix, %tunnel_id, error = %e, "tunnel yamux session ended"),
        Err(e) => warn!(%prefix, %tunnel_id, error = %e, "tunnel yamux task panicked"),
    }

    ping_task.abort();
    state.cleanup_tunnel(&prefix, &tunnel_id);
    info!(%prefix, %tunnel_id, "tunnel disconnected");
}
