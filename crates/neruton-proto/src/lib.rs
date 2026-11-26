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
    build_tunnel_ws_url, generate_uuid_prefix, normalize_target_url, validate_prefix,
    validate_prefix_with_extra_reserved, PrefixError, RESERVED_PREFIXES,
};
pub use types::{
    DeleteTunnelResponse, ErrorResponse, HealthResponse, LogsResponse, RegisterRequest,
    RegisterResponse, RequestLog, ServerEvent, ServerInfo, TunnelInfo, TunnelsResponse,
};
pub use ws_stream::{WsByteStream, WsFrame, WsFrameKind};
pub use yamux_session::{yamux_config, YamuxClient, YamuxError, YamuxServer};
