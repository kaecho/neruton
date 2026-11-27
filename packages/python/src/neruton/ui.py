"""Terminal UI formatting mirroring `crates/neruton-cli/src/ui.rs`."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from typing import Any, Optional, TextIO

from ._version import __version__
from .protocol import RegisterResponse


def _use_color() -> bool:
    return "NO_COLOR" not in os.environ


def _c(code: str, text: str) -> str:
    if _use_color():
        return f"\x1b[{code}m{text}\x1b[0m"
    return text


def _now_hms() -> str:
    return datetime.now().strftime("%H:%M:%S")


def print_banner(
    resp: RegisterResponse,
    target_url: str,
    *,
    transport_info: Optional[Any] = None,
    stream: Optional[TextIO] = None,
) -> None:
    """Print the online tunnel status box matching Rust `neruton` CLI."""
    out = stream if stream is not None else sys.stdout
    if resp.owner_username and resp.token_name:
        auth_label = f"{resp.owner_username} ({resp.token_name})"
    elif resp.owner_username:
        auth_label = resp.owner_username
    elif resp.token_name:
        auth_label = resp.token_name
    else:
        auth_label = "anonymous (open mode)"

    rows = [
        ("Wildcard URL", resp.public_url, "1;36"),
        ("Web Preview", resp.preview_url, "1;32"),
        ("Path URL", resp.path_url, "36"),
        ("Dashboard", resp.dashboard_url, "34"),
        ("Forwarding", target_url, "33"),
        ("Prefix", resp.prefix, "1;35"),
        ("Auth", auth_label, "37"),
    ]
    if transport_info is not None:
        summary = (
            transport_info.summary()
            if hasattr(transport_info, "summary") and callable(transport_info.summary)
            else str(transport_info)
        )
        rows.append(("Transport", summary, "32"))

    label_width = max(len(label) for label, _, _ in rows)
    val_width = max(len(value) for _, value, _ in rows)
    title = f" Neruton Tunnel v{__version__} · Online "
    inner_width = max(label_width + 3 + val_width, len(title)) + 2

    top_fill = max(0, inner_width - len(title))
    left_fill = min(2, top_fill)
    right_fill = max(0, top_fill - left_fill)

    print(file=out)
    print(
        f"{_c('36', '╭' + '─' * left_fill)}"
        f"{_c('1;32', title)}"
        f"{_c('36', '─' * right_fill)}"
        f"{_c('36', '╮')}",
        file=out,
    )

    for label, value, color in rows:
        pad_label = " " * max(0, label_width - len(label))
        content_len = label_width + 3 + len(value)
        pad_right = " " * max(0, inner_width - content_len - 2)
        print(
            f"{_c('36', '│')} "
            f"{_c('2', label)}{pad_label} "
            f"{_c('2', '→')} "
            f"{_c(color, value)}{pad_right} "
            f"{_c('36', '│')}",
            file=out,
        )

    print(_c("36", f"╰{'─' * inner_width}╯"), file=out)
    print(_c("2", "Press Ctrl+C to close the tunnel.\n"), file=out, flush=True)


def log_request(
    method: str,
    path: str,
    status: int,
    duration_ms: int,
    *,
    stream: Optional[TextIO] = None,
) -> None:
    out = stream if stream is not None else sys.stdout
    now = _now_hms()
    if status == 101:
        status_color = "1;35"
    elif 200 <= status <= 299:
        status_color = "1;32"
    elif 300 <= status <= 399:
        status_color = "1;36"
    elif 400 <= status <= 499:
        status_color = "1;33"
    else:
        status_color = "1;31"
    status_text = f"{status:3d}"
    method_text = f"{method:<7}"
    print(
        f"{_c('2', now)}  {_c(status_color, status_text)}  "
        f"{_c('1', method_text)}  {path}  {_c('2', f'({duration_ms}ms)')}",
        file=out,
        flush=True,
    )


def log_info(msg: str, *, stream: Optional[TextIO] = None) -> None:
    out = stream if stream is not None else sys.stdout
    print(f"{_c('2', _now_hms())}  {_c('1;36', 'INFO')}  {msg}", file=out, flush=True)


def log_warn(msg: str, *, stream: Optional[TextIO] = None) -> None:
    out = stream if stream is not None else sys.stderr
    print(f"{_c('2', _now_hms())}  {_c('1;33', 'WARN')}  {msg}", file=out, flush=True)


def log_error(msg: str, *, stream: Optional[TextIO] = None) -> None:
    out = stream if stream is not None else sys.stderr
    print(f"{_c('2', _now_hms())}  {_c('1;31', 'ERR ')}  {msg}", file=out, flush=True)
