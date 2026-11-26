use serde::{Deserialize, Serialize};

/// Role assigned to a Neruton web account.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    #[default]
    User,
}

impl UserRole {
    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// Public representation of a user account (never exposes password hash or token_version).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserPublic {
    pub id: String,
    pub username: String,
    pub role: UserRole,
    pub enabled: bool,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

/// Extended user record returned on admin user management endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserAdminView {
    #[serde(flatten)]
    pub user: UserPublic,
    pub token_count: usize,
    pub active_tunnel_count: usize,
}

/// Summary of a persisted tunnel token (never exposes raw secret or SHA-256 hash).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenSummary {
    pub id: String,
    pub name: String,
    pub token_prefix: String,
    pub owner_id: String,
    pub owner_username: String,
    pub enabled: bool,
    pub allowed_prefixes: Vec<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// One-time token creation payload containing the raw `ntk_...` secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenCreatedResponse {
    pub token: TokenSummary,
    pub secret: String,
}

/// `GET /_neruton/api/tokens` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokensResponse {
    pub tokens: Vec<TokenSummary>,
}

/// `PATCH /_neruton/api/tokens/:id` response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub token: TokenSummary,
}

/// `POST /_neruton/api/tokens` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    pub name: String,
    #[serde(default)]
    pub allowed_prefixes: Option<Vec<String>>,
}

/// `PATCH /_neruton/api/tokens/:id` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTokenRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub allowed_prefixes: Option<Vec<String>>,
}

/// `GET /_neruton/api/auth/status` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStatusResponse {
    pub needs_setup: bool,
    pub authenticated: bool,
    pub user: Option<UserPublic>,
    pub panel_host: String,
    pub base_domain: String,
    pub public_scheme: String,
    pub version: String,
}

/// `POST /_neruton/api/auth/setup` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupRequest {
    pub username: String,
    pub password: String,
}

/// `POST /_neruton/api/auth/setup` response payload (`201 Created`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupResponse {
    pub user: UserPublic,
    pub initial_token: TokenCreatedResponse,
}

/// `POST /_neruton/api/auth/login` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// `POST /_neruton/api/auth/login` and `GET /_neruton/api/auth/me` response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUserResponse {
    pub user: UserPublic,
}

/// `POST /_neruton/api/auth/password` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// Generic `{ "ok": true }` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OkResponse {
    pub ok: bool,
}

/// `GET /_neruton/api/users` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsersResponse {
    pub users: Vec<UserAdminView>,
}

/// `POST /_neruton/api/users` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: UserRole,
}

/// `PATCH /_neruton/api/users/:id` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub role: Option<UserRole>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub password: Option<String>,
}

/// `POST /_neruton/api/users` and `PATCH /_neruton/api/users/:id` response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub user: UserAdminView,
}

/// `GET /_neruton/api/settings` and `PATCH /_neruton/api/settings` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsResponse {
    pub require_tunnel_auth: bool,
    pub max_tunnels_per_user: u32,
    pub reserved_prefixes: Vec<String>,
    pub default_reserved_prefixes: Vec<String>,
    pub env_token_configured: bool,
}

/// `PATCH /_neruton/api/settings` request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettingsRequest {
    #[serde(default)]
    pub require_tunnel_auth: Option<bool>,
    #[serde(default)]
    pub max_tunnels_per_user: Option<u32>,
    #[serde(default)]
    pub reserved_prefixes: Option<Vec<String>>,
}

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
    #[serde(default)]
    pub owner_username: Option<String>,
    #[serde(default)]
    pub token_name: Option<String>,
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
            owner_username: None,
            token_name: None,
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
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub owner_username: Option<String>,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub token_name: Option<String>,
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
    pub require_tunnel_auth: bool,
    pub auth_required: bool,
    pub uptime_secs: u64,
    pub active_tunnels: usize,
    pub total_requests: u64,
    pub total_users: usize,
    pub total_tokens: usize,
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
