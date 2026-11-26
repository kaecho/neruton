use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use dashmap::{DashMap, DashSet};
use http::HeaderMap;
use neruton_proto::{
    HealthResponse, RequestLog, ServerEvent, ServerInfo, TunnelInfo, YamuxClient, VERSION,
};
use tokio::sync::broadcast;

use crate::config::ServerConfig;

pub const MAX_LOGS: usize = 200;

pub struct ActiveTunnel {
    pub id: String,
    pub prefix: String,
    pub public_url: String,
    pub path_url: String,
    pub preview_url: String,
    pub target_url: String,
    pub client_version: String,
    pub client_os: String,
    pub remote_addr: String,
    pub connected_at: String,
    pub requests_total: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub active_streams: AtomicU64,
    pub latency_ms: Arc<AtomicU64>,
    pub disconnected_emitted: AtomicBool,
    pub yamux: YamuxClient,
    logs: RwLock<VecDeque<RequestLog>>,
}

impl ActiveTunnel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        prefix: String,
        public_url: String,
        path_url: String,
        preview_url: String,
        target_url: String,
        client_version: String,
        client_os: String,
        remote_addr: String,
        connected_at: String,
        latency_ms: Arc<AtomicU64>,
        yamux: YamuxClient,
    ) -> Self {
        Self {
            id,
            prefix,
            public_url,
            path_url,
            preview_url,
            target_url,
            client_version,
            client_os,
            remote_addr,
            connected_at,
            requests_total: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            active_streams: AtomicU64::new(0),
            latency_ms,
            disconnected_emitted: AtomicBool::new(false),
            yamux,
            logs: RwLock::new(VecDeque::with_capacity(MAX_LOGS)),
        }
    }

    pub fn to_info(&self) -> TunnelInfo {
        TunnelInfo {
            id: self.id.clone(),
            prefix: self.prefix.clone(),
            public_url: self.public_url.clone(),
            path_url: self.path_url.clone(),
            preview_url: self.preview_url.clone(),
            target_url: self.target_url.clone(),
            client_version: self.client_version.clone(),
            client_os: self.client_os.clone(),
            remote_addr: self.remote_addr.clone(),
            connected_at: self.connected_at.clone(),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            latency_ms: self.latency_ms.load(Ordering::Relaxed),
            status: "online".to_string(),
        }
    }

    pub fn push_log(&self, log: RequestLog) {
        if let Ok(mut guard) = self.logs.write() {
            guard.push_front(log);
            guard.truncate(MAX_LOGS);
        }
    }

    pub fn recent_logs(&self) -> Vec<RequestLog> {
        self.logs
            .read()
            .map(|guard| guard.iter().cloned().collect())
            .unwrap_or_default()
    }
}

pub struct AppState {
    pub config: ServerConfig,
    pub started_at: Instant,
    pub tunnels: DashMap<String, Arc<ActiveTunnel>>,
    pub reserved_prefixes: DashSet<String>,
    global_logs: RwLock<VecDeque<RequestLog>>,
    pub total_requests: AtomicU64,
    pub events_tx: broadcast::Sender<ServerEvent>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Arc<Self> {
        let (events_tx, _) = broadcast::channel(512);
        Arc::new(Self {
            config,
            started_at: Instant::now(),
            tunnels: DashMap::new(),
            reserved_prefixes: DashSet::new(),
            global_logs: RwLock::new(VecDeque::with_capacity(MAX_LOGS)),
            total_requests: AtomicU64::new(0),
            events_tx,
        })
    }

    /// Normalize a `Host` header value by stripping port, trimming whitespace/trailing dots,
    /// and lowercasing.
    pub fn normalize_host(raw: &str) -> String {
        let trimmed = raw.trim();
        // Handle IPv6 bracket notation `[::1]:8080`
        let without_port = if trimmed.starts_with('[') {
            if let Some(end) = trimmed.find(']') {
                &trimmed[..=end]
            } else {
                trimmed
            }
        } else if let Some((host, _port)) = trimmed.rsplit_once(':') {
            host
        } else {
            trimmed
        };
        without_port.trim_end_matches('.').to_ascii_lowercase()
    }

    /// If `normalized_host` is a wildcard subdomain under `NERUTON_BASE_DOMAIN` and NOT
    /// `NERUTON_PANEL_HOST`, returns `Some(prefix)`.
    pub fn extract_wildcard_prefix(&self, normalized_host: &str) -> Option<String> {
        let panel_host = self.config.panel_host();
        if normalized_host == panel_host {
            return None;
        }
        let suffix = format!(".{}", self.config.base_domain());
        let prefix = normalized_host.strip_suffix(&suffix)?;
        if prefix.is_empty() {
            return None;
        }
        Some(prefix.to_string())
    }

    /// Verify optional Bearer token (from `Authorization: Bearer <token>` or `?token=<token>`).
    pub fn is_authorized(&self, headers: &HeaderMap, query_token: Option<&str>) -> bool {
        let Some(expected) = self.config.auth_token() else {
            return true;
        };
        if let Some(auth_val) = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(token) = auth_val
                .strip_prefix("Bearer ")
                .or_else(|| auth_val.strip_prefix("bearer "))
            {
                if constant_time_eq(token.trim().as_bytes(), expected.as_bytes()) {
                    return true;
                }
            }
        }
        if let Some(token) = query_token {
            if constant_time_eq(token.trim().as_bytes(), expected.as_bytes()) {
                return true;
            }
        }
        false
    }

    pub fn emit_event(&self, event: ServerEvent) {
        let _ = self.events_tx.send(event);
    }

    pub fn record_request(&self, tunnel: &ActiveTunnel, log: RequestLog) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        tunnel.requests_total.fetch_add(1, Ordering::Relaxed);
        tunnel.bytes_in.fetch_add(log.bytes_in, Ordering::Relaxed);
        tunnel.bytes_out.fetch_add(log.bytes_out, Ordering::Relaxed);
        tunnel.push_log(log.clone());
        if let Ok(mut guard) = self.global_logs.write() {
            guard.push_front(log.clone());
            guard.truncate(MAX_LOGS);
        }
        self.emit_event(ServerEvent::RequestLogged { log });
    }

    pub fn global_logs(&self) -> Vec<RequestLog> {
        self.global_logs
            .read()
            .map(|guard| guard.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn list_tunnels(&self) -> Vec<TunnelInfo> {
        let mut items: Vec<TunnelInfo> = self.tunnels.iter().map(|e| e.value().to_info()).collect();
        items.sort_by(|a, b| b.connected_at.cmp(&a.connected_at));
        items
    }

    pub fn get_tunnel(&self, prefix: &str) -> Option<Arc<ActiveTunnel>> {
        let key = prefix.trim().to_ascii_lowercase();
        self.tunnels.get(&key).map(|e| e.value().clone())
    }

    /// Force-disconnect an active tunnel (used by `DELETE /_neruton/api/tunnels/:prefix`).
    pub fn disconnect_tunnel(&self, prefix: &str) -> Option<Arc<ActiveTunnel>> {
        let key = prefix.trim().to_ascii_lowercase();
        let (_, tunnel) = self.tunnels.remove(&key)?;
        tunnel.yamux.close();
        if !tunnel.disconnected_emitted.swap(true, Ordering::SeqCst) {
            self.emit_event(ServerEvent::TunnelDisconnected {
                prefix: tunnel.prefix.clone(),
                tunnel_id: tunnel.id.clone(),
            });
        }
        Some(tunnel)
    }

    /// Remove tunnel upon natural WebSocket termination (guarded by `tunnel_id` to prevent races).
    pub fn cleanup_tunnel(&self, prefix: &str, tunnel_id: &str) {
        let removed = self
            .tunnels
            .remove_if(prefix, |_, existing| existing.id == tunnel_id);
        if let Some((_, tunnel)) = removed {
            if !tunnel.disconnected_emitted.swap(true, Ordering::SeqCst) {
                self.emit_event(ServerEvent::TunnelDisconnected {
                    prefix: tunnel.prefix.clone(),
                    tunnel_id: tunnel.id.clone(),
                });
            }
        }
    }

    pub fn health(&self) -> HealthResponse {
        HealthResponse {
            status: "ok".to_string(),
            version: VERSION.to_string(),
            base_domain: self.config.base_domain(),
            panel_host: self.config.panel_host(),
            auth_required: self.config.auth_token().is_some(),
            active_tunnels: self.tunnels.len(),
        }
    }

    pub fn server_info(&self) -> ServerInfo {
        ServerInfo {
            version: VERSION.to_string(),
            base_domain: self.config.base_domain(),
            panel_host: self.config.panel_host(),
            public_scheme: self.config.public_scheme(),
            auth_required: self.config.auth_token().is_some(),
            uptime_secs: self.started_at.elapsed().as_secs(),
            active_tunnels: self.tunnels.len(),
            total_requests: self.total_requests.load(Ordering::Relaxed),
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
