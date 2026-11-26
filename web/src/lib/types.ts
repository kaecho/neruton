export type UserRole = "admin" | "user";

export interface UserPublic {
  id: string;
  username: string;
  role: UserRole;
  enabled: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface UserAdminView extends UserPublic {
  token_count: number;
  active_tunnel_count: number;
}

export interface TokenSummary {
  id: string;
  name: string;
  token_prefix: string;
  owner_id: string;
  owner_username: string;
  enabled: boolean;
  allowed_prefixes: string[];
  created_at: string;
  last_used_at: string | null;
}

export interface CreateTokenResponse {
  token: TokenSummary;
  secret: string;
}

export interface AuthStatusResponse {
  needs_setup: boolean;
  authenticated: boolean;
  user: UserPublic | null;
  panel_host: string;
  base_domain: string;
  public_scheme: string;
  version: string;
}

export interface SetupResponse {
  user: UserPublic;
  initial_token: CreateTokenResponse;
}

export interface LoginResponse {
  user: UserPublic;
}

export interface MeResponse {
  user: UserPublic;
}

export interface ServerInfo {
  version: string;
  base_domain: string;
  panel_host: string;
  public_scheme: string;
  require_tunnel_auth: boolean;
  auth_required: boolean;
  uptime_secs: number;
  active_tunnels: number;
  total_requests: number;
  total_users?: number;
  total_tokens?: number;
}

export interface TunnelInfo {
  id: string;
  prefix: string;
  public_url: string;
  path_url: string;
  preview_url: string;
  target_url: string;
  client_version: string;
  client_os: string;
  remote_addr: string;
  connected_at: string;
  requests_total: number;
  bytes_in: number;
  bytes_out: number;
  active_streams: number;
  latency_ms: number | null;
  status: string;
  owner_id?: string | null;
  owner_username?: string | null;
  token_id?: string | null;
  token_name?: string | null;
}

export interface RequestLog {
  id: string;
  tunnel_prefix: string;
  timestamp: string;
  method: string;
  path: string;
  host: string;
  via: "subdomain" | "path" | string;
  status: number;
  duration_ms: number;
  bytes_in: number;
  bytes_out: number;
  client_ip: string;
  user_agent: string;
}

export interface SettingsResponse {
  require_tunnel_auth: boolean;
  max_tunnels_per_user: number;
  reserved_prefixes: string[];
  default_reserved_prefixes: string[];
  env_token_configured: boolean;
}

export interface UpdateSettingsPayload {
  require_tunnel_auth?: boolean;
  max_tunnels_per_user?: number;
  reserved_prefixes?: string[];
}

export type SseConnectionState = "connecting" | "connected" | "polling" | "error";

export type ViewportMode = "desktop" | "tablet" | "mobile";

export interface TunnelsResponse {
  tunnels: TunnelInfo[];
}

export interface LogsResponse {
  logs: RequestLog[];
}

export interface TokensResponse {
  tokens: TokenSummary[];
}

export interface UsersResponse {
  users: UserAdminView[];
}
