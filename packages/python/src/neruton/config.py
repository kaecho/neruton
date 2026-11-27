"""Persistent configuration helpers compatible with Rust `~/.config/neruton/config.toml`."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence, Tuple, Union

from ._version import DEFAULT_SERVER_URL
from .doh import DohConfig, parse_doh_option
from .errors import NerutonError
from .tls_stealth import normalize_sni_mode

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib  # type: ignore[import-not-found]


@dataclass
class Config:
    """Neruton CLI/SDK configuration stored in `config.toml` (string-only keys for cross-client compat)."""

    server: Optional[str] = None
    token: Optional[str] = None
    doh: Optional[str] = None
    sni_mode: Optional[str] = None
    sni: Optional[str] = None
    ech_config: Optional[str] = None


@dataclass(frozen=True)
class StealthOptions:
    """Resolved DoH & TLS SNI hiding options."""

    doh: DohConfig
    sni_mode: str = "auto"
    sni: Optional[str] = None
    ech_config: Optional[str] = None


def config_path(explicit: Optional[Union[str, Path]] = None) -> Path:
    """Return the resolved path to `config.toml`.

    Matches Rust `neruton-cli`:
    - Explicit path if provided.
    - On Unix (Linux/macOS): `~/.config/neruton/config.toml`.
    - On Windows: `%APPDATA%\\neruton\\config.toml` (falling back to home dir).
    """
    if explicit is not None:
        return Path(explicit).expanduser()

    if os.name != "nt":
        return Path.home() / ".config" / "neruton" / "config.toml"

    appdata = os.environ.get("APPDATA")
    base = Path(appdata) if appdata else Path.home()
    return base / "neruton" / "config.toml"


def _clean_opt(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed if trimmed else None


def load_config(path: Optional[Union[str, Path]] = None) -> Config:
    """Load `Config` from `config.toml`, returning an empty `Config` if the file does not exist."""
    target = config_path(path)
    if not target.exists():
        return Config()

    try:
        raw_bytes = target.read_bytes()
    except OSError as exc:
        raise NerutonError(f"failed to read config file {target}: {exc}") from exc

    try:
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise NerutonError(f"failed to parse TOML config {target}: {exc}") from exc

    fields = ("server", "token", "doh", "sni_mode", "sni", "ech_config")
    values = {}
    for key in fields:
        val = data.get(key)
        if val is not None and not isinstance(val, str):
            raise NerutonError(f"invalid '{key}' field in {target}: expected string")
        values[key] = val

    return Config(**values)


def _escape_toml_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize_config_toml(cfg: Config) -> str:
    lines = []
    for key in ("server", "token", "doh", "sni_mode", "sni", "ech_config"):
        val = getattr(cfg, key)
        if val is not None:
            lines.append(f"{key} = {_escape_toml_string(val)}")
    return ("\n".join(lines) + "\n") if lines else ""


def save_config(
    config: Optional[Config] = None,
    path: Optional[Union[str, Path]] = None,
    *,
    server: Optional[str] = None,
    token: Optional[str] = None,
    doh: Optional[str] = None,
    sni_mode: Optional[str] = None,
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
) -> Path:
    """Persist `Config` to `config.toml` with `0600` permissions on POSIX systems."""
    if config is None:
        cfg = Config(
            server=server,
            token=token,
            doh=doh,
            sni_mode=sni_mode,
            sni=sni,
            ech_config=ech_config,
        )
    else:
        cfg = Config(
            server=server if server is not None else config.server,
            token=token if token is not None else config.token,
            doh=doh if doh is not None else config.doh,
            sni_mode=sni_mode if sni_mode is not None else config.sni_mode,
            sni=sni if sni is not None else config.sni,
            ech_config=ech_config if ech_config is not None else config.ech_config,
        )

    target = config_path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise NerutonError(f"failed to create config directory {target.parent}: {exc}") from exc

    content = _serialize_config_toml(cfg).encode("utf-8")

    try:
        if os.name != "nt":
            # Create/replace atomically with mode 0600 so secrets are never world-readable.
            tmp_path = target.with_name(f".{target.name}.{os.getpid()}.tmp")
            fd = os.open(
                str(tmp_path),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            try:
                os.write(fd, content)
            finally:
                os.close(fd)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, target)
            os.chmod(target, 0o600)
        else:
            target.write_bytes(content)
    except OSError as exc:
        raise NerutonError(f"failed to write config file {target}: {exc}") from exc

    return target


def resolve_server_and_token(
    *,
    server: Optional[str] = None,
    token: Optional[str] = None,
    config_file: Optional[Union[str, Path]] = None,
) -> Tuple[str, Optional[str]]:
    """Resolve effective `(server, token)` following Rust CLI precedence.

    - server: explicit arg > `NERUTON_SERVER` > `config.toml` > `https://neruton.moer.eu.org`
    - token: explicit arg > `NERUTON_TOKEN` > `NERUTON_AUTH_TOKEN` > `config.toml` > `None`
    """
    file_cfg = load_config(config_file)

    resolved_server = (
        _clean_opt(server)
        or _clean_opt(os.environ.get("NERUTON_SERVER"))
        or _clean_opt(file_cfg.server)
        or DEFAULT_SERVER_URL
    )
    resolved_token = (
        _clean_opt(token)
        or _clean_opt(os.environ.get("NERUTON_TOKEN"))
        or _clean_opt(os.environ.get("NERUTON_AUTH_TOKEN"))
        or _clean_opt(file_cfg.token)
    )
    return resolved_server, resolved_token


def resolve_stealth_options(
    *,
    doh: Optional[Union[bool, str, Sequence[str]]] = None,
    sni_mode: Optional[str] = None,
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
    config_file: Optional[Union[str, Path]] = None,
) -> StealthOptions:
    """Resolve effective DoH & SNI hiding options with strict cross-client precedence.

    Precedence: explicit arg/CLI flag > env var > `config.toml` > defaults (`doh="auto"`, `sni_mode="auto"`).
    Env vars: `NERUTON_DOH`, `NERUTON_SNI_MODE`, `NERUTON_SNI`, `NERUTON_ECH_CONFIG`.
    """
    file_cfg = load_config(config_file)

    if doh is not None:
        if isinstance(doh, str) and not doh.strip():
            raw_doh: Union[bool, str, Sequence[str]] = (
                _clean_opt(os.environ.get("NERUTON_DOH"))
                or _clean_opt(file_cfg.doh)
                or "auto"
            )
        else:
            raw_doh = doh
    else:
        raw_doh = (
            _clean_opt(os.environ.get("NERUTON_DOH"))
            or _clean_opt(file_cfg.doh)
            or "auto"
        )

    resolved_doh = parse_doh_option(raw_doh)

    raw_sni_mode = (
        _clean_opt(sni_mode)
        or _clean_opt(os.environ.get("NERUTON_SNI_MODE"))
        or _clean_opt(file_cfg.sni_mode)
        or "auto"
    )
    resolved_sni_mode = normalize_sni_mode(raw_sni_mode)

    resolved_sni = (
        _clean_opt(sni)
        or _clean_opt(os.environ.get("NERUTON_SNI"))
        or _clean_opt(file_cfg.sni)
    )
    resolved_ech = (
        _clean_opt(ech_config)
        or _clean_opt(os.environ.get("NERUTON_ECH_CONFIG"))
        or _clean_opt(file_cfg.ech_config)
    )

    return StealthOptions(
        doh=resolved_doh,
        sni_mode=resolved_sni_mode,
        sni=resolved_sni,
        ech_config=resolved_ech,
    )
