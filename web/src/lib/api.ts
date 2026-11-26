import type {
  AuthStatusResponse,
  CreateTokenResponse,
  LoginResponse,
  LogsResponse,
  MeResponse,
  RequestLog,
  ServerInfo,
  SettingsResponse,
  SetupResponse,
  TokenSummary,
  TokensResponse,
  TunnelInfo,
  TunnelsResponse,
  UpdateSettingsPayload,
  UserAdminView,
  UserRole,
  UsersResponse,
} from "./types";

export class ApiError extends Error {
  status: number;
  unauthorized: boolean;
  forbidden: boolean;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.unauthorized = status === 401;
    this.forbidden = status === 403;
  }
}

async function parseJsonOrThrow<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body && typeof body.error === "string") {
        detail = body.error;
      } else if (body && typeof body.message === "string") {
        detail = body.message;
      }
    } catch {
      try {
        const text = await res.text();
        if (text) detail = text.slice(0, 200);
      } catch {
        // Keep HTTP status detail
      }
    }
    throw new ApiError(detail, res.status);
  }
  return (await res.json()) as T;
}

async function apiFetch<T>(
  input: string,
  init: RequestInit = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const res = await fetch(input, {
    ...init,
    headers,
    credentials: "include",
    cache: "no-store",
  });
  return parseJsonOrThrow<T>(res);
}

/* ── Auth Endpoints ───────────────────────────────────────────────── */

export function fetchAuthStatus(
  signal?: AbortSignal,
): Promise<AuthStatusResponse> {
  return apiFetch<AuthStatusResponse>("/_neruton/api/auth/status", { signal });
}

export function setupAdminAccount(payload: {
  username: string;
  password: string;
}): Promise<SetupResponse> {
  return apiFetch<SetupResponse>("/_neruton/api/auth/setup", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function loginAccount(payload: {
  username: string;
  password: string;
}): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/_neruton/api/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function logoutAccount(): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>("/_neruton/api/auth/logout", {
    method: "POST",
  });
}

export function fetchCurrentUser(signal?: AbortSignal): Promise<MeResponse> {
  return apiFetch<MeResponse>("/_neruton/api/auth/me", { signal });
}

export function changeOwnPassword(payload: {
  current_password: string;
  new_password: string;
}): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>("/_neruton/api/auth/password", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

/* ── Server & Tunnels ─────────────────────────────────────────────── */

export function fetchServerInfo(signal?: AbortSignal): Promise<ServerInfo> {
  return apiFetch<ServerInfo>("/_neruton/api/info", { signal });
}

export async function fetchTunnels(signal?: AbortSignal): Promise<TunnelInfo[]> {
  const data = await apiFetch<TunnelsResponse | TunnelInfo[]>(
    "/_neruton/api/tunnels",
    { signal },
  );
  if (Array.isArray(data)) return data;
  return Array.isArray(data.tunnels) ? data.tunnels : [];
}

export async function fetchTunnel(
  prefix: string,
  signal?: AbortSignal,
): Promise<TunnelInfo | null> {
  const res = await fetch(
    `/_neruton/api/tunnels/${encodeURIComponent(prefix)}`,
    {
      credentials: "include",
      cache: "no-store",
      signal,
    },
  );
  if (res.status === 404) return null;
  return parseJsonOrThrow<TunnelInfo>(res);
}

export async function disconnectTunnel(prefix: string): Promise<void> {
  await apiFetch<unknown>(
    `/_neruton/api/tunnels/${encodeURIComponent(prefix)}`,
    { method: "DELETE" },
  );
}

/* ── Logs ─────────────────────────────────────────────────────────── */

export async function fetchLogs(
  prefix?: string,
  signal?: AbortSignal,
): Promise<RequestLog[]> {
  const url = prefix
    ? `/_neruton/api/tunnels/${encodeURIComponent(prefix)}/logs`
    : "/_neruton/api/logs";
  const res = await fetch(url, {
    credentials: "include",
    cache: "no-store",
    signal,
  });
  if (res.status === 404 && prefix) return [];
  const data = await parseJsonOrThrow<LogsResponse | RequestLog[]>(res);
  if (Array.isArray(data)) return data;
  return Array.isArray(data.logs) ? data.logs : [];
}

export function clearAllLogs(): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>("/_neruton/api/logs", {
    method: "DELETE",
  });
}

/* ── Tunnel Tokens ────────────────────────────────────────────────── */

export async function fetchTokens(
  signal?: AbortSignal,
): Promise<TokenSummary[]> {
  const data = await apiFetch<TokensResponse | TokenSummary[]>(
    "/_neruton/api/tokens",
    { signal },
  );
  if (Array.isArray(data)) return data;
  return Array.isArray(data.tokens) ? data.tokens : [];
}

export function createToken(payload: {
  name: string;
  allowed_prefixes?: string[];
}): Promise<CreateTokenResponse> {
  return apiFetch<CreateTokenResponse>("/_neruton/api/tokens", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateToken(
  id: string,
  payload: {
    name?: string;
    enabled?: boolean;
    allowed_prefixes?: string[];
  },
): Promise<TokenSummary> {
  const data = await apiFetch<{ token: TokenSummary }>(
    `/_neruton/api/tokens/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload),
    },
  );
  return data.token;
}

export function deleteToken(id: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(
    `/_neruton/api/tokens/${encodeURIComponent(id)}`,
    { method: "DELETE" },
  );
}

/* ── Users (Admin only) ───────────────────────────────────────────── */

export async function fetchUsers(
  signal?: AbortSignal,
): Promise<UserAdminView[]> {
  const data = await apiFetch<UsersResponse | UserAdminView[]>(
    "/_neruton/api/users",
    { signal },
  );
  if (Array.isArray(data)) return data;
  return Array.isArray(data.users) ? data.users : [];
}

export async function createUser(payload: {
  username: string;
  password: string;
  role: UserRole;
}): Promise<UserAdminView> {
  const data = await apiFetch<{ user: UserAdminView }>("/_neruton/api/users", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  return data.user;
}

export async function updateUser(
  id: string,
  payload: {
    role?: UserRole;
    enabled?: boolean;
    password?: string;
  },
): Promise<UserAdminView> {
  const data = await apiFetch<{ user: UserAdminView }>(
    `/_neruton/api/users/${encodeURIComponent(id)}`,
    {
      method: "PATCH",
      body: JSON.stringify(payload),
    },
  );
  return data.user;
}

export function deleteUser(id: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(
    `/_neruton/api/users/${encodeURIComponent(id)}`,
    { method: "DELETE" },
  );
}

/* ── Settings ─────────────────────────────────────────────────────── */

export function fetchSettings(
  signal?: AbortSignal,
): Promise<SettingsResponse> {
  return apiFetch<SettingsResponse>("/_neruton/api/settings", { signal });
}

export function updateSettings(
  payload: UpdateSettingsPayload,
): Promise<SettingsResponse> {
  return apiFetch<SettingsResponse>("/_neruton/api/settings", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

/* ── URL Helpers ──────────────────────────────────────────────────── */

const DEFAULT_BASE_DOMAIN = process.env.NEXT_PUBLIC_BASE_DOMAIN || "";
const DEFAULT_PANEL_HOST = process.env.NEXT_PUBLIC_PANEL_HOST || "";

export function resolvePanelHost(
  info?: { panel_host?: string } | null,
): string {
  if (info?.panel_host) return info.panel_host;
  if (typeof window !== "undefined" && window.location.host) {
    return window.location.host;
  }
  return DEFAULT_PANEL_HOST || "localhost";
}

export function resolveCliServerArg(
  info?: { panel_host?: string; public_scheme?: string } | null,
): string {
  const host = resolvePanelHost(info);
  if (host.includes(":")) return host;
  const scheme = info?.public_scheme || "https";
  return `${host}:${scheme === "http" ? "80" : "443"}`;
}

export function resolvePanelOrigin(
  info?: { panel_host?: string; public_scheme?: string } | null,
): string {
  if (info?.panel_host) {
    const scheme = info.public_scheme || "https";
    return `${scheme}://${info.panel_host}`;
  }
  if (typeof window !== "undefined") {
    return window.location.origin;
  }
  return `https://${DEFAULT_PANEL_HOST || "localhost"}`;
}

export function resolveWildcardUrl(
  prefix: string,
  info?: { base_domain?: string; public_scheme?: string } | null,
  tunnel?: TunnelInfo | null,
): string {
  if (tunnel?.public_url) return tunnel.public_url;
  const scheme = info?.public_scheme || "https";
  const baseDomain =
    info?.base_domain ||
    DEFAULT_BASE_DOMAIN ||
    (typeof window !== "undefined" ? window.location.hostname : "localhost");
  return `${scheme}://${prefix}.${baseDomain}`;
}

export function resolvePathUrl(
  prefix: string,
  info?: { panel_host?: string; public_scheme?: string } | null,
  tunnel?: TunnelInfo | null,
): string {
  if (tunnel?.path_url) return tunnel.path_url;
  return `${resolvePanelOrigin(info)}/t/${encodeURIComponent(prefix)}/`;
}
