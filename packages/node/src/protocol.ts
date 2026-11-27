import crypto from 'node:crypto';
import { RESERVED_PREFIXES, TUNNEL_WS_PATH } from './constants.js';
import { NerutonError, PrefixError } from './errors.js';

export interface RegisterRequest {
  prefix: string | null;
  target_url: string;
  client_version: string;
  client_os: string;
}

export interface RegisterResponse {
  ok: boolean;
  tunnel_id: string;
  prefix: string;
  public_url: string;
  path_url: string;
  preview_url: string;
  dashboard_url: string;
  error: string | null;
  owner_username?: string | null;
  token_name?: string | null;
}

export interface ErrorResponse {
  error: string;
}

const DNS_LABEL_EDGE_RE = /^[a-z0-9]$/;
const DNS_LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const NUMERIC_PORT_RE = /^\d+$/;

/**
 * Generate a fresh lowercase UUID v4 suitable as a DNS subdomain label.
 */
export function generateUuidPrefix(): string {
  return crypto.randomUUID().toLowerCase();
}

/**
 * Normalize (trim & lowercase) and validate DNS label syntax without checking reserved lists.
 */
export function validatePrefixFormat(raw: string): string {
  const normalized = raw.trim().toLowerCase();
  if (normalized.length === 0) {
    throw new PrefixError('empty', normalized, 'prefix cannot be empty');
  }
  if (normalized.length > 63) {
    throw new PrefixError(
      'too_long',
      normalized,
      `prefix must be 1..=63 characters, got ${normalized.length}`,
    );
  }
  if (
    !DNS_LABEL_EDGE_RE.test(normalized[0]) ||
    !DNS_LABEL_EDGE_RE.test(normalized[normalized.length - 1]) ||
    !DNS_LABEL_RE.test(normalized)
  ) {
    throw new PrefixError(
      'invalid_format',
      normalized,
      `prefix '${normalized}' must match DNS label ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`,
    );
  }
  return normalized;
}

/**
 * Normalize (trim & lowercase) and validate a subdomain prefix against built-in
 * and optional extra reserved prefixes.
 */
export function validatePrefix(raw: string, extraReserved: readonly string[] = []): string {
  const normalized = raw.trim().toLowerCase();
  if (normalized.length === 0) {
    throw new PrefixError('empty', normalized, 'prefix cannot be empty');
  }

  for (const reserved of RESERVED_PREFIXES) {
    if (normalized === reserved) {
      throw new PrefixError('reserved', normalized, `prefix '${normalized}' is reserved`);
    }
  }
  for (const extra of extraReserved) {
    if (normalized === extra.trim().toLowerCase()) {
      throw new PrefixError('reserved', normalized, `prefix '${normalized}' is reserved`);
    }
  }

  return validatePrefixFormat(normalized);
}

/**
 * Convert a user-supplied server URL (`https://...`, `http://...`, `wss://...`, `ws://...`,
 * or bare `host[:port]`) into the tunnel WebSocket endpoint URL (`wss://<host>/_neruton/tunnel`).
 */
export function buildTunnelWsUrl(server: string): URL {
  const trimmed = server.trim();
  if (!trimmed) {
    throw new NerutonError('server URL cannot be empty', 'INVALID_URL');
  }

  let candidate: string;
  if (trimmed.includes('://')) {
    const schemeSep = trimmed.indexOf('://');
    const scheme = trimmed.slice(0, schemeSep).toLowerCase();
    const rest = trimmed.slice(schemeSep + 3);
    if (scheme === 'https') {
      candidate = `wss://${rest}`;
    } else if (scheme === 'http') {
      candidate = `ws://${rest}`;
    } else if (scheme === 'wss' || scheme === 'ws') {
      candidate = `${scheme}://${rest}`;
    } else {
      throw new NerutonError(
        `unsupported server scheme '${scheme}' in '${server}'`,
        'INVALID_URL',
      );
    }
  } else {
    candidate = `wss://${trimmed}`;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch (err) {
    throw new NerutonError(`invalid server URL '${server}'`, 'INVALID_URL', { cause: err });
  }

  if (!url.hostname) {
    throw new NerutonError(`server URL '${server}' is missing a host`, 'INVALID_URL');
  }

  const strippedPath = url.pathname.replace(/\/+$/, '');
  if (strippedPath === '' || strippedPath === '/') {
    url.pathname = TUNNEL_WS_PATH;
  } else if (!strippedPath.endsWith(TUNNEL_WS_PATH)) {
    url.pathname = `${strippedPath}${TUNNEL_WS_PATH}`;
  } else {
    url.pathname = strippedPath;
  }

  return url;
}

/**
 * Normalize a local target specification like `3000`, `localhost:3000`,
 * or `http://127.0.0.1:8080`.
 */
export function normalizeTargetUrl(raw: string | number): URL {
  if (typeof raw === 'number') {
    if (!Number.isInteger(raw) || raw < 1 || raw > 65535) {
      throw new NerutonError(`invalid target port: ${raw}`, 'INVALID_TARGET');
    }
    return new URL(`http://127.0.0.1:${raw}/`);
  }

  const trimmed = raw.trim();
  if (!trimmed) {
    throw new NerutonError('target URL cannot be empty', 'INVALID_TARGET');
  }

  let candidate: string;
  if (NUMERIC_PORT_RE.test(trimmed)) {
    const port = Number(trimmed);
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      throw new NerutonError(`invalid target port '${raw}'`, 'INVALID_TARGET');
    }
    candidate = `http://127.0.0.1:${port}`;
  } else if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    candidate = trimmed;
  } else if (trimmed.includes('://')) {
    throw new NerutonError(
      `unsupported target scheme in '${trimmed}' (expected http:// or https://)`,
      'INVALID_TARGET',
    );
  } else {
    candidate = `http://${trimmed}`;
  }

  let url: URL;
  try {
    url = new URL(candidate);
  } catch (err) {
    throw new NerutonError(`invalid target URL '${raw}'`, 'INVALID_TARGET', { cause: err });
  }

  if (!url.hostname) {
    throw new NerutonError(`target URL '${raw}' is missing a host`, 'INVALID_TARGET');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new NerutonError(
      `unsupported target scheme in '${trimmed}' (expected http:// or https://)`,
      'INVALID_TARGET',
    );
  }

  return url;
}

/**
 * Format OS/arch pair consistent with Rust CLI metadata (e.g. `linux/x86_64`, `macos/aarch64`).
 */
export function formatClientOs(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): string {
  const osName =
    platform === 'darwin'
      ? 'macos'
      : platform === 'win32'
        ? 'windows'
        : platform;
  const archName =
    arch === 'x64'
      ? 'x86_64'
      : arch === 'arm64'
        ? 'aarch64'
        : arch === 'ia32'
          ? 'x86'
          : arch;
  return `${osName}/${archName}`;
}

export function isNonRetryableRejection(errMsg: string): boolean {
  const lower = errMsg.toLowerCase();
  return (
    lower.includes('not permitted') ||
    lower.includes('restricted to specific prefixes') ||
    lower.includes('is reserved') ||
    lower.includes('must match dns label') ||
    lower.includes('tunnel limit reached')
  );
}

export function format401Error(body: Buffer | string | undefined, hadToken: boolean): {
  message: string;
  serverMessage: string | undefined;
} {
  let serverMessage: string | undefined;
  if (body !== undefined) {
    const text = typeof body === 'string' ? body : body.toString('utf8');
    if (text.trim()) {
      try {
        const parsed = JSON.parse(text) as Partial<ErrorResponse>;
        if (typeof parsed.error === 'string' && parsed.error.trim().length > 0) {
          serverMessage = parsed.error.trim();
        }
      } catch {
        // Ignore non-JSON body.
      }
    }
  }

  const detail =
    serverMessage ??
    (hadToken
      ? 'Invalid, disabled, or revoked tunnel token.'
      : 'Authentication token required by this Neruton server.');

  const message = hadToken
    ? `Authentication failed (401 Unauthorized): ${detail}\n  Verify or regenerate your token in the Neruton web panel, then run:\n    neruton config set --token <TOKEN>`
    : `Authentication failed (401 Unauthorized): ${detail}\n  Create a token in the Neruton web panel, then run:\n    neruton config set --token <TOKEN>\n  Or pass --token <TOKEN> (or set NERUTON_TOKEN).`;

  return { message, serverMessage };
}
