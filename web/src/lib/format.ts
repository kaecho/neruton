const DEFAULT_RESERVED_PREFIXES = new Set([
  "neruton",
  "www",
  "api",
  "admin",
  "_neruton",
]);

const PREFIX_REGEX = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const USERNAME_REGEX = /^[a-zA-Z0-9._-]{3,32}$/;

export function formatBytes(bytes: number | null | undefined): string {
  const value =
    typeof bytes === "number" && Number.isFinite(bytes)
      ? Math.max(0, bytes)
      : 0;
  if (value === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const idx = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  const scaled = value / Math.pow(1024, idx);
  return `${scaled >= 100 || idx === 0 ? scaled.toFixed(0) : scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)} ${units[idx]}`;
}

export function formatNumber(value: number | null | undefined): string {
  const safe =
    typeof value === "number" && Number.isFinite(value) ? value : 0;
  return new Intl.NumberFormat("zh-CN").format(safe);
}

export function formatDurationMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "—";
  if (ms < 1) return "<1 ms";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

export function formatUptime(secs: number | null | undefined): string {
  const total =
    typeof secs === "number" && Number.isFinite(secs)
      ? Math.max(0, Math.floor(secs))
      : 0;
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;

  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

export function formatRelativeTime(
  iso: string | null | undefined,
  nowMs = Date.now(),
): string {
  if (!iso) return "从未";
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return iso;
  const diffSec = Math.max(0, Math.floor((nowMs - ts) / 1000));
  if (diffSec < 10) return "刚刚";
  if (diffSec < 60) return `${diffSec} 秒前`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} 分钟前`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr} 小时前`;
  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 30) return `${diffDay} 天前`;
  return formatShortDate(iso);
}

export function formatShortDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const min = String(d.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${min}`;
}

export function formatClockTime(iso: string | null | undefined): string {
  if (!iso) return "--:--:--";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

export interface PrefixValidation {
  valid: boolean;
  normalized: string;
  error?: string;
}

export function validateSubdomainPrefix(
  raw: string,
  extraReserved?: string[],
): PrefixValidation {
  const normalized = raw.trim().toLowerCase();
  if (!normalized) {
    return { valid: false, normalized, error: "请输入子域名前缀，例如 app-dev" };
  }
  if (normalized.length > 63) {
    return { valid: false, normalized, error: "前缀长度不能超过 63 个字符" };
  }
  if (
    DEFAULT_RESERVED_PREFIXES.has(normalized) ||
    extraReserved?.includes(normalized)
  ) {
    return {
      valid: false,
      normalized,
      error: `"${normalized}" 为保留前缀，请更换其他名称`,
    };
  }
  if (!PREFIX_REGEX.test(normalized)) {
    return {
      valid: false,
      normalized,
      error: "仅允许小写字母、数字和连字符 (-)，且不能以连字符开头或结尾",
    };
  }
  return { valid: true, normalized };
}

export function validateUsername(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return "请输入用户名";
  if (!USERNAME_REGEX.test(trimmed)) {
    return "用户名需为 3-32 位字母、数字或 . _ -";
  }
  return null;
}

export function parsePrefixList(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(/[\s,，]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    ),
  );
}

export async function copyToClipboard(text: string): Promise<boolean> {
  if (typeof window === "undefined") return false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback below
  }

  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.top = "-9999px";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}

export function isUuidLike(prefix: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    prefix,
  );
}
