import type {
  LogsResponse,
  RequestLog,
  ServerInfo,
  TunnelInfo,
  TunnelsResponse,
} from "./types";

const ADMIN_TOKEN_KEY = "neruton_admin_token";

export class ApiError extends Error {
  status: number;
  unauthorized: boolean;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.unauthorized = status === 401 || status === 403;
  }
}

export function getStoredAdminToken(): string {
  if (typeof window === "undefined") return "";
  try {
    return window.localStorage.getItem(ADMIN_TOKEN_KEY) || "";
  } catch {
    return "";
  }
}

export function setStoredAdminToken(token: string): void {
  if (typeof window === "undefined") return;
  try {
    const trimmed = token.trim();
    if (trimmed) {
      window.localStorage.setItem(ADMIN_TOKEN_KEY, trimmed);
    } else {
      window.localStorage.removeItem(ADMIN_TOKEN_KEY);
    }
  } catch {
    // ignore storage errors
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
        // keep default detail
      }
    }
    throw new ApiError(detail, res.status);
  }
  return (await res.json()) as T;
}

export async function fetchServerInfo(signal?: AbortSignal): Promise<ServerInfo> {
  const res = await fetch("/_neruton/api/info", {
    cache: "no-store",
    signal,
  });
  return parseJsonOrThrow<ServerInfo>(res);
}

export async function fetchTunnels(signal?: AbortSignal): Promise<TunnelInfo[]> {
  const res = await fetch("/_neruton/api/tunnels", {
    cache: "no-store",
    signal,
  });
  const data = await parseJsonOrThrow<TunnelsResponse | TunnelInfo[]>(res);
  if (Array.isArray(data)) return data;
  return Array.isArray(data.tunnels) ? data.tunnels : [];
}

export async function fetchTunnel(prefix: string, signal?: AbortSignal): Promise<TunnelInfo | null> {
  const res = await fetch(`/_neruton/api/tunnels/${encodeURIComponent(prefix)}`, {
    cache: "no-store",
    signal,
  });
  if (res.status === 404) return null;
  return parseJsonOrThrow<TunnelInfo>(res);
}

export async function disconnectTunnel(prefix: string, token?: string): Promise<void> {
  const headers: HeadersInit = {};
  const resolvedToken = (token ?? getStoredAdminToken()).trim();
  if (resolvedToken) {
    headers["Authorization"] = `Bearer ${resolvedToken}`;
  }
  const res = await fetch(`/_neruton/api/tunnels/${encodeURIComponent(prefix)}`, {
    method: "DELETE",
    headers,
    cache: "no-store",
  });
  if (!res.ok) {
    await parseJsonOrThrow<unknown>(res);
  }
}

export async function fetchLogs(prefix?: string, signal?: AbortSignal): Promise<RequestLog[]> {
  const url = prefix
    ? `/_neruton/api/tunnels/${encodeURIComponent(prefix)}/logs`
    : "/_neruton/api/logs";
  const res = await fetch(url, {
    cache: "no-store",
    signal,
  });
  if (res.status === 404 && prefix) return [];
  const data = await parseJsonOrThrow<LogsResponse | RequestLog[]>(res);
  if (Array.isArray(data)) return data;
  return Array.isArray(data.logs) ? data.logs : [];
}

const DEFAULT_BASE_DOMAIN =
  process.env.NEXT_PUBLIC_BASE_DOMAIN || "moer.eu.org";
const DEFAULT_PANEL_HOST =
  process.env.NEXT_PUBLIC_PANEL_HOST || "neruton.moer.eu.org";

export function resolvePanelOrigin(info: ServerInfo | null): string {
  if (info?.panel_host) {
    const scheme = info.public_scheme || "https";
    return `${scheme}://${info.panel_host}`;
  }
  if (typeof window !== "undefined") {
    return window.location.origin;
  }
  return `https://${DEFAULT_PANEL_HOST}`;
}

export function resolveWildcardUrl(prefix: string, info: ServerInfo | null, tunnel?: TunnelInfo | null): string {
  if (tunnel?.public_url) return tunnel.public_url;
  const scheme = info?.public_scheme || "https";
  const baseDomain = info?.base_domain || DEFAULT_BASE_DOMAIN;
  return `${scheme}://${prefix}.${baseDomain}`;
}

export function resolvePathUrl(prefix: string, info: ServerInfo | null, tunnel?: TunnelInfo | null): string {
  if (tunnel?.path_url) return tunnel.path_url;
  return `${resolvePanelOrigin(info)}/t/${encodeURIComponent(prefix)}/`;
}

export function resolvePreviewUrl(prefix: string, info: ServerInfo | null, tunnel?: TunnelInfo | null): string {
  if (tunnel?.preview_url) return tunnel.preview_url;
  return `${resolvePanelOrigin(info)}/preview/${encodeURIComponent(prefix)}`;
}
