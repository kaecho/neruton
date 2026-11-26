pub mod prefix;
pub mod types;
pub mod ws_stream;
pub mod yamux_session;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_BASE_DOMAIN: &str = "moer.eu.org";
pub const DEFAULT_PANEL_HOST: &str = "neruton.moer.eu.org";
pub const DEFAULT_PUBLIC_SCHEME: &str = "https";
pub const TUNNEL_WS_PATH: &str = "/_neruton/tunnel";

pub use prefix::{
    build_tunnel_ws_url, generate_uuid_prefix, normalize_target_url, validate_password,
    validate_prefix, validate_prefix_format, validate_prefix_with_extra_reserved,
    validate_prefix_with_reserved_list, validate_username, PrefixError, RESERVED_PREFIXES,
};
pub use types::{
    AuthStatusResponse, AuthUserResponse, ChangePasswordRequest, CreateTokenRequest,
    CreateUserRequest, DeleteTunnelResponse, ErrorResponse, HealthResponse, LoginRequest,
    LogsResponse, OkResponse, RegisterRequest, RegisterResponse, RequestLog, ServerEvent,
    ServerInfo, SettingsResponse, SetupRequest, SetupResponse, TokenCreatedResponse, TokenResponse,
    TokenSummary, TokensResponse, TunnelInfo, TunnelsResponse, UpdateSettingsRequest,
    UpdateTokenRequest, UpdateUserRequest, UserAdminView, UserPublic, UserResponse, UserRole,
    UsersResponse,
};
pub use ws_stream::{WsByteStream, WsFrame, WsFrameKind};
pub use yamux_session::{yamux_config, YamuxClient, YamuxError, YamuxServer};
