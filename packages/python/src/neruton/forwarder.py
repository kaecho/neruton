"""Local HTTP/1.1 & WebSocket stream forwarder matching `crates/neruton-cli/src/forwarder.rs`."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass
from enum import Enum
from http import HTTPStatus
from typing import Any, Callable, List, Optional, Protocol, Tuple
from urllib.parse import urlsplit

from .yamux import YamuxStream

HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "proxy-connection",
    }
)

_MAX_HEADER_BYTES = 128 * 1024
_IO_CHUNK_SIZE = 32 * 1024


class HostHeaderKind(Enum):
    REWRITE_TO_TARGET = "rewrite"
    PRESERVE = "preserve"
    CUSTOM = "custom"


@dataclass(frozen=True)
class HostHeaderMode:
    kind: HostHeaderKind = HostHeaderKind.REWRITE_TO_TARGET
    custom_value: Optional[str] = None

    @classmethod
    def from_option(cls, value: Optional[str]) -> HostHeaderMode:
        if value is None:
            return cls(HostHeaderKind.REWRITE_TO_TARGET)
        trimmed = value.strip()
        lower = trimmed.lower()
        if not trimmed or lower == "rewrite":
            return cls(HostHeaderKind.REWRITE_TO_TARGET)
        if lower == "preserve":
            return cls(HostHeaderKind.PRESERVE)
        return cls(HostHeaderKind.CUSTOM, trimmed)


@dataclass(frozen=True)
class RequestEvent:
    """Metadata emitted after forwarding an HTTP or WebSocket request."""

    method: str
    path: str
    status: int
    duration_ms: int


RequestCallback = Callable[[RequestEvent], None]


@dataclass
class TargetConfig:
    """Resolved local upstream service configuration."""

    url: str
    scheme_https: bool
    host: str
    port: int
    default_host_header: str
    base_path: str
    host_header_mode: HostHeaderMode
    no_tls_verify: bool = False
    ssl_context: Optional[ssl.SSLContext] = None

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        host_header: Optional[str] = None,
        no_tls_verify: bool = False,
    ) -> TargetConfig:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme == "https":
            scheme_https = True
        elif scheme == "http":
            scheme_https = False
        else:
            raise ValueError(f"unsupported target scheme '{scheme}' (expected http or https)")

        host = parsed.hostname
        if not host:
            raise ValueError("target URL is missing a host")

        default_port = 443 if scheme_https else 80
        explicit_port = parsed.port
        port = explicit_port if explicit_port is not None else default_port

        host_display = f"[{host}]" if ":" in host else host
        if explicit_port is not None and explicit_port != default_port:
            default_host_header = f"{host_display}:{explicit_port}"
        else:
            default_host_header = host_display

        base_path = parsed.path.rstrip("/")

        ssl_ctx: Optional[ssl.SSLContext] = None
        if scheme_https:
            ssl_ctx = build_ssl_context(no_tls_verify=no_tls_verify)

        return cls(
            url=url,
            scheme_https=scheme_https,
            host=host,
            port=port,
            default_host_header=default_host_header,
            base_path=base_path,
            host_header_mode=HostHeaderMode.from_option(host_header),
            no_tls_verify=no_tls_verify,
            ssl_context=ssl_ctx,
        )


def build_ssl_context(*, no_tls_verify: bool = False) -> ssl.SSLContext:
    """Build an SSLContext using system CAs or skipping verification if requested."""
    ctx = ssl.create_default_context()
    if no_tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _Readable(Protocol):
    async def read(self, n: int) -> bytes: ...


class _BufferedReader:
    """Buffered async reader preserving unread trailing bytes (critical for 101 upgrades)."""

    def __init__(self, stream: _Readable) -> None:
        self._stream = stream
        self._buf = bytearray()
        self._eof = False

    def take_buffer(self) -> bytes:
        if not self._buf:
            return b""
        data = bytes(self._buf)
        self._buf.clear()
        return data

    async def _fill(self) -> bool:
        if self._eof:
            return False
        chunk = await self._stream.read(_IO_CHUNK_SIZE)
        if not chunk:
            self._eof = True
            return False
        self._buf.extend(chunk)
        return True

    async def read_until(self, delimiter: bytes, max_bytes: int = _MAX_HEADER_BYTES) -> bytes:
        """Read up to and including `delimiter`. Returns `b''` on clean EOF before any bytes."""
        while True:
            idx = self._buf.find(delimiter)
            if idx != -1:
                end = idx + len(delimiter)
                out = bytes(self._buf[:end])
                del self._buf[:end]
                return out
            if len(self._buf) > max_bytes:
                raise ValueError(f"HTTP header block exceeds {max_bytes} bytes")
            if not await self._fill():
                if not self._buf:
                    return b""
                raise EOFError("unexpected EOF while reading HTTP headers")

    async def read_line(self, max_bytes: int = 16 * 1024) -> bytes:
        line = await self.read_until(b"\r\n", max_bytes=max_bytes)
        if not line:
            raise EOFError("unexpected EOF while reading HTTP chunk line")
        return line

    async def read_exact(self, n: int) -> bytes:
        if n <= 0:
            return b""
        while len(self._buf) < n:
            if not await self._fill():
                raise EOFError(f"unexpected EOF: needed {n} bytes, got {len(self._buf)}")
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    async def read_some(self, max_len: int = _IO_CHUNK_SIZE) -> bytes:
        if self._buf:
            out = bytes(self._buf[:max_len])
            del self._buf[:max_len]
            return out
        if self._eof:
            return b""
        chunk = await self._stream.read(max_len)
        if not chunk:
            self._eof = True
            return b""
        return chunk


def is_upgrade_request(headers: List[Tuple[str, str]]) -> bool:
    has_upgrade = False
    has_conn_upgrade = False
    for name, value in headers:
        lower = name.lower()
        if lower == "upgrade":
            has_upgrade = True
        elif lower == "connection":
            if any(part.strip().lower() == "upgrade" for part in value.split(",")):
                has_conn_upgrade = True
    return has_upgrade and has_conn_upgrade


def is_websocket_upgrade(headers: List[Tuple[str, str]]) -> bool:
    if not is_upgrade_request(headers):
        return False
    for name, value in headers:
        if name.lower() == "upgrade" and value.strip().lower() == "websocket":
            return True
    return False


def is_hop_by_hop(name: str, *, preserve_upgrade: bool) -> bool:
    lower = name.lower()
    if preserve_upgrade and lower in ("connection", "upgrade"):
        return False
    return lower in HOP_BY_HOP_HEADERS


def _parse_headers_block(raw: bytes) -> Tuple[str, List[Tuple[str, str]]]:
    text = raw[:-4].decode("latin-1")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("empty HTTP start line")
    start_line = lines[0]
    headers: List[Tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if ":" not in line:
            raise ValueError(f"malformed HTTP header line: {line!r}")
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return start_line, headers


def _has_chunked_encoding(headers: List[Tuple[str, str]]) -> bool:
    for name, value in headers:
        if name.lower() == "transfer-encoding":
            if any(part.strip().lower() == "chunked" for part in value.split(",")):
                return True
    return False


def _get_content_length(headers: List[Tuple[str, str]]) -> Optional[int]:
    for name, value in headers:
        if name.lower() == "content-length":
            try:
                cl = int(value.strip())
                if cl >= 0:
                    return cl
            except ValueError:
                return None
    return None


def _should_close_connection(version: str, headers: List[Tuple[str, str]]) -> bool:
    conn_tokens = set()
    for name, value in headers:
        if name.lower() == "connection":
            for part in value.split(","):
                tok = part.strip().lower()
                if tok:
                    conn_tokens.add(tok)
    if "close" in conn_tokens:
        return True
    if version.upper() == "HTTP/1.0" and "keep-alive" not in conn_tokens:
        return True
    return False


def _reason_phrase(status: int, raw_reason: str = "") -> str:
    if raw_reason:
        return raw_reason
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return ""


def _build_plain_error_response(status: int, message: str) -> bytes:
    body = message.encode("utf-8")
    reason = _reason_phrase(status)
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1")
    return head + body


def _rewrite_forward_path(base_path: str, orig_path: str) -> str:
    if not base_path:
        return orig_path
    if orig_path.startswith("/"):
        return f"{base_path}{orig_path}"
    return f"{base_path}/{orig_path}"


def _build_forwarded_request_headers(
    method: str,
    forward_path: str,
    in_headers: List[Tuple[str, str]],
    target: TargetConfig,
    *,
    is_upgrade: bool,
    body_mode: str,
) -> bytes:
    out_headers: List[Tuple[str, str]] = []
    mode = target.host_header_mode

    for name, value in in_headers:
        if is_hop_by_hop(name, preserve_upgrade=is_upgrade):
            continue
        lower_name = name.lower()
        if body_mode == "chunked" and lower_name == "content-length":
            continue
        if lower_name == "host":
            if mode.kind == HostHeaderKind.PRESERVE:
                out_headers.append((name, value))
            continue
        out_headers.append((name, value))

    if mode.kind == HostHeaderKind.REWRITE_TO_TARGET:
        out_headers.append(("Host", target.default_host_header))
    elif mode.kind == HostHeaderKind.CUSTOM and mode.custom_value is not None:
        out_headers.append(("Host", mode.custom_value))

    if body_mode == "chunked":
        out_headers.append(("Transfer-Encoding", "chunked"))

    if not is_upgrade:
        out_headers.append(("Connection", "close"))

    lines = [f"{method} {forward_path} HTTP/1.1"]
    for name, value in out_headers:
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("latin-1")


async def _connect_target(
    target: TargetConfig,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if target.scheme_https:
        reader, writer = await asyncio.open_connection(
            host=target.host,
            port=target.port,
            ssl=target.ssl_context,
            server_hostname=target.host,
        )
    else:
        reader, writer = await asyncio.open_connection(
            host=target.host,
            port=target.port,
        )

    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    return reader, writer


def _parse_chunk_size(size_line: bytes) -> int:
    size_str = size_line[:-2].split(b";", 1)[0].strip()
    if not size_str or not all(
        (48 <= b <= 57) or (65 <= b <= 70) or (97 <= b <= 102) for b in size_str
    ):
        raise ValueError(f"invalid HTTP chunk size: {size_str!r}")
    return int(size_str, 16)


async def _forward_chunked_body_to_writer(
    src: _BufferedReader,
    dst: asyncio.StreamWriter,
) -> None:
    while True:
        size_line = await src.read_line()
        chunk_size = _parse_chunk_size(size_line)
        if chunk_size == 0:
            # Consume optional trailers until empty CRLF line.
            while True:
                trailer_line = await src.read_line()
                if trailer_line == b"\r\n":
                    break
            dst.write(b"0\r\n\r\n")
            await dst.drain()
            return
        chunk = await src.read_exact(chunk_size)
        crlf = await src.read_exact(2)
        if crlf != b"\r\n":
            raise ValueError("invalid chunk terminator in request body")
        dst.write(f"{chunk_size:x}\r\n".encode("ascii") + chunk + b"\r\n")
        await dst.drain()


async def _forward_fixed_body_to_writer(
    src: _BufferedReader,
    dst: asyncio.StreamWriter,
    remaining: int,
) -> None:
    while remaining > 0:
        chunk = await src.read_some(min(remaining, _IO_CHUNK_SIZE))
        if not chunk:
            raise EOFError("unexpected EOF reading request body")
        dst.write(chunk)
        await dst.drain()
        remaining -= len(chunk)


async def _forward_request_body_guarded(
    coro: Any,
    local_writer: asyncio.StreamWriter,
) -> None:
    try:
        await coro
    except asyncio.CancelledError:
        raise
    except Exception:
        # Close upstream socket so neither the local service nor our response reader hangs
        # when an incoming request body is malformed or truncated.
        try:
            local_writer.close()
        except Exception:
            pass
        raise


async def _forward_chunked_body_to_yamux(
    src: _BufferedReader,
    dst: YamuxStream,
) -> None:
    while True:
        size_line = await src.read_line()
        chunk_size = _parse_chunk_size(size_line)
        if chunk_size == 0:
            while True:
                trailer_line = await src.read_line()
                if trailer_line == b"\r\n":
                    break
            await dst.write(b"0\r\n\r\n")
            return
        chunk = await src.read_exact(chunk_size)
        crlf = await src.read_exact(2)
        if crlf != b"\r\n":
            raise ValueError("invalid chunk terminator in response body")
        await dst.write(f"{chunk_size:x}\r\n".encode("ascii") + chunk + b"\r\n")


async def _forward_fixed_body_to_yamux(
    src: _BufferedReader,
    dst: YamuxStream,
    remaining: int,
) -> None:
    while remaining > 0:
        chunk = await src.read_some(min(remaining, _IO_CHUNK_SIZE))
        if not chunk:
            raise EOFError("unexpected EOF reading upstream response body")
        await dst.write(chunk)
        remaining -= len(chunk)


async def _forward_eof_body_as_chunked_to_yamux(
    src: _BufferedReader,
    dst: YamuxStream,
) -> None:
    while True:
        chunk = await src.read_some(_IO_CHUNK_SIZE)
        if not chunk:
            break
        await dst.write(f"{len(chunk):x}\r\n".encode("ascii") + chunk + b"\r\n")
    await dst.write(b"0\r\n\r\n")


async def _bridge_upgraded_streams(
    yamux_reader: _BufferedReader,
    yamux_stream: YamuxStream,
    local_reader: _BufferedReader,
    local_writer: asyncio.StreamWriter,
) -> None:
    async def yamux_to_local() -> None:
        try:
            leftover = yamux_reader.take_buffer()
            if leftover:
                local_writer.write(leftover)
                await local_writer.drain()
            while True:
                data = await yamux_stream.read(_IO_CHUNK_SIZE)
                if not data:
                    break
                local_writer.write(data)
                await local_writer.drain()
            if local_writer.can_write_eof():
                local_writer.write_eof()
        except Exception:
            pass

    async def local_to_yamux() -> None:
        try:
            leftover = local_reader.take_buffer()
            if leftover:
                await yamux_stream.write(leftover)
            while True:
                data = await local_reader.read_some(_IO_CHUNK_SIZE)
                if not data:
                    break
                await yamux_stream.write(data)
            await yamux_stream.write_eof()
        except Exception:
            pass

    t1 = asyncio.create_task(yamux_to_local())
    t2 = asyncio.create_task(local_to_yamux())
    try:
        await asyncio.gather(t1, t2)
    finally:
        for t in (t1, t2):
            if not t.done():
                t.cancel()


def _emit_request_event(
    on_request: Optional[RequestCallback],
    method: str,
    path: str,
    status: int,
    started_at: float,
) -> None:
    if on_request is None:
        return
    ms = int((time.monotonic() - started_at) * 1000)
    try:
        on_request(RequestEvent(method=method, path=path, status=status, duration_ms=ms))
    except Exception:
        pass


async def _close_writer(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass


async def handle_yamux_stream(
    stream: YamuxStream,
    target: TargetConfig,
    *,
    on_request: Optional[RequestCallback] = None,
) -> None:
    """Serve an inbound Yamux stream carrying HTTP/1.1 (or upgraded WebSocket) traffic."""
    yamux_reader = _BufferedReader(stream)

    try:
        while True:
            raw_req_head = await yamux_reader.read_until(b"\r\n\r\n")
            if not raw_req_head:
                # Clean EOF between keep-alive requests.
                break

            started_at = time.monotonic()
            try:
                start_line, req_headers = _parse_headers_block(raw_req_head)
                parts = start_line.split(" ", 2)
                if len(parts) != 3:
                    raise ValueError(f"invalid HTTP request line: {start_line!r}")
                method, orig_path, req_version = parts
            except ValueError as exc:
                await stream.write(_build_plain_error_response(400, f"neruton: bad request: {exc}"))
                break

            is_upgrade = is_upgrade_request(req_headers)
            is_ws = is_websocket_upgrade(req_headers)
            log_method = "WS" if is_ws else method
            client_wants_close = _should_close_connection(req_version, req_headers)

            if _has_chunked_encoding(req_headers):
                req_body_mode = "chunked"
                req_content_length = 0
            else:
                cl = _get_content_length(req_headers)
                if cl is not None and cl > 0:
                    req_body_mode = "length"
                    req_content_length = cl
                else:
                    req_body_mode = "none"
                    req_content_length = 0

            local_writer: Optional[asyncio.StreamWriter] = None
            body_task: Optional[asyncio.Task[None]] = None
            headers_sent = False

            try:
                try:
                    local_reader_raw, local_writer = await _connect_target(target)
                except Exception as exc:
                    _emit_request_event(on_request, log_method, orig_path, 502, started_at)
                    err_resp = _build_plain_error_response(
                        502,
                        f"neruton: failed to connect to local service {target.url}: {exc}",
                    )
                    await stream.write(err_resp)
                    break

                forward_path = _rewrite_forward_path(target.base_path, orig_path)
                req_bytes = _build_forwarded_request_headers(
                    method,
                    forward_path,
                    req_headers,
                    target,
                    is_upgrade=is_upgrade,
                    body_mode=req_body_mode,
                )
                local_writer.write(req_bytes)
                await local_writer.drain()

                # Forward request body concurrently to prevent bidirectional deadlocks on
                # large streaming uploads or echo endpoints.
                if req_body_mode == "chunked":
                    body_task = asyncio.create_task(
                        _forward_request_body_guarded(
                            _forward_chunked_body_to_writer(yamux_reader, local_writer),
                            local_writer,
                        )
                    )
                elif req_body_mode == "length":
                    body_task = asyncio.create_task(
                        _forward_request_body_guarded(
                            _forward_fixed_body_to_writer(
                                yamux_reader, local_writer, req_content_length
                            ),
                            local_writer,
                        )
                    )

                local_buf = _BufferedReader(local_reader_raw)

                # Read response headers, forwarding any 1xx interim responses (e.g. 100 Continue).
                while True:
                    raw_resp_head = await local_buf.read_until(b"\r\n\r\n")
                    if not raw_resp_head:
                        raise EOFError("local service closed connection before response headers")
                    resp_start, resp_headers = _parse_headers_block(raw_resp_head)
                    rparts = resp_start.split(" ", 2)
                    if len(rparts) < 2:
                        raise ValueError(f"invalid upstream HTTP status line: {resp_start!r}")
                    status = int(rparts[1])
                    reason = rparts[2] if len(rparts) > 2 else _reason_phrase(status)

                    if 100 <= status < 200 and status != 101:
                        await stream.write(raw_resp_head)
                        continue
                    break

                _emit_request_event(on_request, log_method, orig_path, status, started_at)

                # 101 Switching Protocols: preserve all headers verbatim and pipe raw bytes.
                if status == 101:
                    if body_task is not None:
                        await body_task
                        body_task = None
                    lines = [f"HTTP/1.1 101 {reason}"]
                    for name, value in resp_headers:
                        lines.append(f"{name}: {value}")
                    lines.append("")
                    lines.append("")
                    await stream.write("\r\n".join(lines).encode("latin-1"))
                    headers_sent = True

                    await _bridge_upgraded_streams(
                        yamux_reader, stream, local_buf, local_writer
                    )
                    return

                # Standard HTTP response (>= 200).
                no_body = method.upper() == "HEAD" or status in (204, 304)
                resp_is_chunked = (not no_body) and _has_chunked_encoding(resp_headers)
                resp_cl = None if (no_body or resp_is_chunked) else _get_content_length(resp_headers)
                resp_eof_delimited = (not no_body) and (not resp_is_chunked) and (resp_cl is None)

                out_resp_headers: List[Tuple[str, str]] = []
                for name, value in resp_headers:
                    if is_hop_by_hop(name, preserve_upgrade=False):
                        continue
                    if resp_is_chunked and name.lower() == "content-length":
                        continue
                    out_resp_headers.append((name, value))

                if resp_is_chunked or resp_eof_delimited:
                    out_resp_headers.append(("Transfer-Encoding", "chunked"))

                resp_lines = [f"HTTP/1.1 {status} {reason}"]
                for name, value in out_resp_headers:
                    resp_lines.append(f"{name}: {value}")
                resp_lines.append("")
                resp_lines.append("")
                await stream.write("\r\n".join(resp_lines).encode("latin-1"))
                headers_sent = True

                if no_body:
                    pass
                elif resp_is_chunked:
                    await _forward_chunked_body_to_yamux(local_buf, stream)
                elif resp_cl is not None:
                    await _forward_fixed_body_to_yamux(local_buf, stream, resp_cl)
                else:
                    await _forward_eof_body_as_chunked_to_yamux(local_buf, stream)

                body_incomplete = False
                if body_task is not None:
                    if not body_task.done():
                        body_incomplete = True
                        body_task.cancel()
                    try:
                        await body_task
                    except (asyncio.CancelledError, Exception):
                        body_incomplete = True
                    body_task = None

                if client_wants_close or body_incomplete:
                    break

            except Exception as exc:
                body_exc: Optional[BaseException] = None
                if body_task is not None:
                    if not body_task.done():
                        body_task.cancel()
                    try:
                        await body_task
                    except asyncio.CancelledError:
                        pass
                    except Exception as b_exc:
                        body_exc = b_exc
                    body_task = None
                if not headers_sent:
                    if isinstance(body_exc, ValueError):
                        _emit_request_event(on_request, log_method, orig_path, 400, started_at)
                        try:
                            await stream.write(
                                _build_plain_error_response(
                                    400,
                                    f"neruton: bad request body: {body_exc}",
                                )
                            )
                        except Exception:
                            pass
                    else:
                        _emit_request_event(on_request, log_method, orig_path, 502, started_at)
                        try:
                            await stream.write(
                                _build_plain_error_response(
                                    502,
                                    f"neruton: local service request failed: {exc}",
                                )
                            )
                        except Exception:
                            pass
                else:
                    await stream.reset()
                break
            finally:
                if body_task is not None and not body_task.done():
                    body_task.cancel()
                    try:
                        await body_task
                    except (asyncio.CancelledError, Exception):
                        pass
                await _close_writer(local_writer)
    except Exception:
        await stream.reset()
    finally:
        await stream.write_eof()
