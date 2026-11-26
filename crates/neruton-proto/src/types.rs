use serde::{Deserialize, Serialize};

/// Initial handshake sent by `neruton` CLI over the WebSocket control channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub prefix: Option<String>,
    pub target_url: String,
    pub client_version: String,
    pub client_os: String,
}

/// Server reply to `RegisterRequest` before switching the WebSocket to Yamux binary mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub ok: bool,
    pub tunnel_id: String,
    pub prefix: String,
    pub public_url: String,
    pub path_url: String,
    pub preview_url: String,
    pub dashboard_url: String,
    pub error: Option<String>,
}

impl RegisterResponse {
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            tunnel_id: String::new(),
            prefix: String::new(),
            public_url: String::new(),
            path_url: String::new(),
            preview_url: String::new(),
            dashboard_url: String::new(),
            error: Some(message.into()),
        }
    }
}

/// Active tunnel metadata exposed by management REST API and SSE events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelInfo {
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
    pub requests_total: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub active_streams: u64,
    pub latency_ms: u64,
    pub status: String,
}

/// Single proxied HTTP/WS request log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLog {
    pub id: String,
    pub tunnel_prefix: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub host: String,
    pub via: String,
    pub status: u16,
    pub duration_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub client_ip: String,
    pub user_agent: String,
}

/// `GET /_neruton/health` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub base_domain: String,
    pub panel_host: String,
    pub auth_required: bool,
    pub active_tunnels: usize,
}

/// `GET /_neruton/api/info` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub version: String,
    pub base_domain: String,
    pub panel_host: String,
    pub public_scheme: String,
    pub auth_required: bool,
    pub uptime_secs: u64,
    pub active_tunnels: usize,
    pub total_requests: u64,
}

/// `GET /_neruton/api/tunnels` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelsResponse {
    pub tunnels: Vec<TunnelInfo>,
}

/// `GET /_neruton/api/logs` and `GET /_neruton/api/tunnels/:prefix/logs` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsResponse {
    pub logs: Vec<RequestLog>,
}

/// `DELETE /_neruton/api/tunnels/:prefix` success payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteTunnelResponse {
    pub ok: bool,
    pub prefix: String,
}

/// Standard JSON error payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Real-time SSE events emitted on `GET /_neruton/api/events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    TunnelConnected {
        tunnel: TunnelInfo,
    },
    TunnelDisconnected {
        prefix: String,
        tunnel_id: String,
    },
    RequestLogged {
        log: RequestLog,
    },
    Heartbeat {
        timestamp: String,
        active_tunnels: usize,
        total_requests: u64,
    },
}
