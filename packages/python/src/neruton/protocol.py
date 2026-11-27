"""Neruton wire-protocol helpers: prefix validation, URL normalization, and control frames."""

from __future__ import annotations

import json
import platform
import re
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit, urlunsplit

from ._version import TUNNEL_WS_PATH, __version__
from .errors import PrefixError

# Reserved subdomain labels matching `crates/neruton-proto/src/prefix.rs`.
RESERVED_PREFIXES: Tuple[str, ...] = (
    "neruton",
    "www",
    "api",
    "admin",
    "_neruton",
)

_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

_NON_RETRYABLE_PATTERNS: Tuple[str, ...] = (
    "not permitted",
    "restricted to specific prefixes",
    "is reserved",
    "must match dns label",
    "tunnel limit reached",
)


def generate_uuid_prefix() -> str:
    """Generate a fresh lowercase UUID v4 string suitable as a DNS subdomain label."""
    return str(uuid.uuid4())


def validate_prefix_format(raw: str) -> str:
    """Normalize (trim & ASCII lowercase) and validate DNS label syntax."""
    normalized = raw.strip().lower()
    if not normalized:
        raise PrefixError("prefix cannot be empty", code="empty")
    if len(normalized) > 63:
        raise PrefixError(
            f"prefix must be 1..=63 characters, got {len(normalized)}",
            code="too_long",
        )
    if not normalized.isascii() or not _DNS_LABEL_RE.match(normalized):
        raise PrefixError(
            f"prefix '{normalized}' must match DNS label ^[a-z0-9]([a-z0-9-]{{0,61}}[a-z0-9])?$",
            code="invalid_format",
        )
    return normalized


def validate_prefix(
    raw: str,
    *,
    extra_reserved: Sequence[str] = (),
) -> str:
    """Normalize and validate a subdomain prefix against built-in and extra reserved lists."""
    normalized = raw.strip().lower()
    if not normalized:
        raise PrefixError("prefix cannot be empty", code="empty")

    # Check reserved names before DNS character checks so e.g. "_neruton" reports reserved.
    if normalized in RESERVED_PREFIXES:
        raise PrefixError(f"prefix '{normalized}' is reserved", code="reserved")
    for extra in extra_reserved:
        if normalized == extra.strip().lower():
            raise PrefixError(f"prefix '{normalized}' is reserved", code="reserved")

    return validate_prefix_format(normalized)


def _format_netloc(
    hostname: str,
    port: Optional[int],
    default_port: int,
    userinfo: Optional[str] = None,
) -> str:
    host_part = f"[{hostname}]" if ":" in hostname and not hostname.startswith("[") else hostname
    if port is not None and port != default_port:
        host_port = f"{host_part}:{port}"
    else:
        host_port = host_part
    if userinfo:
        return f"{userinfo}@{host_port}"
    return host_port


def build_tunnel_ws_url(server: str) -> str:
    """Convert a server URL (`https://...`, `http://...`, `wss://...`, `ws://...`, or bare
    `host[:port]`) into the Neruton tunnel WebSocket URL (`wss://<host>/_neruton/tunnel`).
    """
    trimmed = server.strip()
    if not trimmed:
        raise ValueError("server URL cannot be empty")

    with_scheme = trimmed if "://" in trimmed else f"https://{trimmed}"
    parsed = urlsplit(with_scheme)

    scheme_map = {
        "https": "wss",
        "http": "ws",
        "wss": "wss",
        "ws": "ws",
    }
    raw_scheme = parsed.scheme.lower()
    if raw_scheme not in scheme_map:
        raise ValueError(
            f"unsupported server scheme '{parsed.scheme}' (expected http, https, ws, or wss)"
        )
    ws_scheme = scheme_map[raw_scheme]

    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"server URL '{server}' is missing a host")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in server URL '{server}': {exc}") from exc

    default_port = 443 if ws_scheme == "wss" else 80
    userinfo: Optional[str] = None
    if parsed.username is not None:
        userinfo = (
            f"{parsed.username}:{parsed.password}"
            if parsed.password is not None
            else parsed.username
        )
    netloc = _format_netloc(hostname, port, default_port, userinfo)

    clean_path = parsed.path.rstrip("/")
    if not clean_path:
        ws_path = TUNNEL_WS_PATH
    elif clean_path.endswith(TUNNEL_WS_PATH):
        ws_path = clean_path
    else:
        ws_path = f"{clean_path}{TUNNEL_WS_PATH}"

    return urlunsplit((ws_scheme, netloc, ws_path, parsed.query, ""))


def normalize_target_url(raw: Union[str, int]) -> str:
    """Normalize a local target spec like `3000`, `localhost:3000`, or `http://127.0.0.1:8080`."""
    if isinstance(raw, bool):
        raise ValueError("target URL cannot be a boolean")
    if isinstance(raw, int):
        if raw < 1 or raw > 65535:
            raise ValueError(f"invalid port {raw} (expected 1..=65535)")
        return f"http://127.0.0.1:{raw}/"

    trimmed = raw.strip()
    if not trimmed:
        raise ValueError("target URL cannot be empty")

    if trimmed.isdigit():
        port_num = int(trimmed)
        if 0 <= port_num <= 65535:
            return f"http://127.0.0.1:{port_num}/"
        raise ValueError(f"invalid port '{trimmed}' (expected 0..=65535)")

    lower = trimmed.lower()
    if lower.startswith("http://") or lower.startswith("https://"):
        candidate = trimmed
    elif "://" in trimmed:
        raise ValueError(
            f"unsupported target scheme in '{trimmed}' (expected http:// or https://)"
        )
    else:
        candidate = f"http://{trimmed}"

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(
            f"unsupported target scheme in '{trimmed}' (expected http:// or https://)"
        )
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"target URL '{raw}' is missing a host")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid target URL '{raw}': {exc}") from exc

    default_port = 443 if scheme == "https" else 80
    netloc = _format_netloc(hostname, port, default_port)
    path = parsed.path if parsed.path else "/"
    return urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))


def detect_client_os() -> str:
    """Return client OS/arch string formatted like Rust (`linux/x86_64`, `macos/aarch64`)."""
    sys_name = platform.system().lower()
    if sys_name == "darwin":
        os_part = "macos"
    elif sys_name:
        os_part = sys_name
    else:
        os_part = "unknown"

    machine = platform.machine().lower()
    arch_map = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "arm64": "aarch64",
        "i386": "x86",
        "i686": "x86",
    }
    arch_part = arch_map.get(machine, machine or "unknown")
    return f"{os_part}/{arch_part}"


def is_non_retryable_rejection(err_msg: str) -> bool:
    """Return True if a registration rejection error message should fail fast without retrying."""
    lower = err_msg.lower()
    return any(pat in lower for pat in _NON_RETRYABLE_PATTERNS)


def format_401_error(body: Optional[bytes], had_token: bool) -> Tuple[str, Optional[str]]:
    """Build a clear diagnostic message for HTTP 401 responses, matching `neruton` CLI."""
    server_msg: Optional[str] = None
    if body:
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict):
                raw_err = parsed.get("error")
                if isinstance(raw_err, str) and raw_err.strip():
                    server_msg = raw_err.strip()
        except (ValueError, UnicodeDecodeError):
            pass

    if server_msg:
        detail = server_msg
    elif had_token:
        detail = "Invalid, disabled, or revoked tunnel token."
    else:
        detail = "Authentication token required by this Neruton server."

    if had_token:
        msg = (
            f"Authentication failed (401 Unauthorized): {detail}\n"
            "  Verify or regenerate your token in the Neruton web panel, then run:\n"
            "    neruton config set --token <TOKEN>"
        )
    else:
        msg = (
            f"Authentication failed (401 Unauthorized): {detail}\n"
            "  Create a token in the Neruton web panel, then run:\n"
            "    neruton config set --token <TOKEN>\n"
            "  Or pass --token <TOKEN> (or set NERUTON_TOKEN)."
        )
    return msg, server_msg


@dataclass(frozen=True)
class RegisterRequest:
    """Initial JSON handshake sent by the client over the WebSocket control channel."""

    prefix: Optional[str]
    target_url: str
    client_version: str = __version__
    client_os: str = ""

    def __post_init__(self) -> None:
        if not self.client_os:
            object.__setattr__(self, "client_os", detect_client_os())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "prefix": self.prefix,
            "target_url": self.target_url,
            "client_version": self.client_version,
            "client_os": self.client_os,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> RegisterRequest:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("RegisterRequest JSON must be an object")
        return cls(
            prefix=data.get("prefix"),
            target_url=str(data["target_url"]),
            client_version=str(data.get("client_version", "")),
            client_os=str(data.get("client_os", "")),
        )


@dataclass(frozen=True)
class RegisterResponse:
    """Server reply to `RegisterRequest` before switching WebSocket to Yamux binary mode."""

    ok: bool
    tunnel_id: str = ""
    prefix: str = ""
    public_url: str = ""
    path_url: str = ""
    preview_url: str = ""
    dashboard_url: str = ""
    error: Optional[str] = None
    owner_username: Optional[str] = None
    token_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "tunnel_id": self.tunnel_id,
            "prefix": self.prefix,
            "public_url": self.public_url,
            "path_url": self.path_url,
            "preview_url": self.preview_url,
            "dashboard_url": self.dashboard_url,
            "error": self.error,
            "owner_username": self.owner_username,
            "token_name": self.token_name,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> RegisterResponse:
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("RegisterResponse JSON must be an object")
        if "ok" not in data or not isinstance(data["ok"], bool):
            raise ValueError("RegisterResponse missing boolean 'ok' field")
        return cls(
            ok=data["ok"],
            tunnel_id=str(data.get("tunnel_id") or ""),
            prefix=str(data.get("prefix") or ""),
            public_url=str(data.get("public_url") or ""),
            path_url=str(data.get("path_url") or ""),
            preview_url=str(data.get("preview_url") or ""),
            dashboard_url=str(data.get("dashboard_url") or ""),
            error=data.get("error") if isinstance(data.get("error"), str) else None,
            owner_username=(
                data.get("owner_username")
                if isinstance(data.get("owner_username"), str)
                else None
            ),
            token_name=(
                data.get("token_name")
                if isinstance(data.get("token_name"), str)
                else None
            ),
        )
