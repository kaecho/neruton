export interface ServerInfo {
  version: string;
  base_domain: string;
  panel_host: string;
  public_scheme: string;
  auth_required: boolean;
  uptime_secs: number;
  active_tunnels: number;
  total_requests: number;
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

export type SseConnectionState = "connecting" | "connected" | "polling" | "error";

export type ViewportMode = "desktop" | "tablet" | "mobile";

export interface TunnelsResponse {
  tunnels: TunnelInfo[];
}

export interface LogsResponse {
  logs: RequestLog[];
}
