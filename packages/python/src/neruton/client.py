"""Async & Sync Neruton tunnel client API over WebSocket + Yamux."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Generator, Optional, Sequence, Set, Tuple, Union
from urllib.parse import urlsplit

import websockets
import websockets.exceptions

from ._version import __version__
from .config import resolve_server_and_token, resolve_stealth_options
from .doh import DohConfig, DohResult, parse_ech_public_name, should_skip_doh
from .errors import (
    AuthError,
    NerutonError,
    RegistrationError,
    TunnelConnectionError,
    TunnelError,
)
from .forwarder import (
    RequestCallback,
    TargetConfig,
    build_ssl_context,
    handle_yamux_stream,
)
from .hpke import select_ech_public_name
from .protocol import (
    RegisterRequest,
    RegisterResponse,
    build_tunnel_ws_url,
    format_401_error,
    is_non_retryable_rejection,
    normalize_target_url,
    validate_prefix,
)
from .tls13_ech import (
    EchConfigError,
    EchRejectedError,
    connect_tls13_ech,
)
from .tls_stealth import (
    TlsStealthPlan,
    TransportInfo,
    build_stealth_ssl_context,
    connect_system_tcp_socket,
    connect_tcp_socket,
    decode_ech_config_option,
    normalize_sni_mode,
    resolve_target_ips,
    resolve_tls_plan,
    upgrade_transport_tls,
)
from .yamux import GoAwayCode, Mode, WsByteTransport, YamuxSession

logger = logging.getLogger("neruton.client")

try:
    from websockets.asyncio.client import connect as _ws_connect_modern
    from websockets.uri import parse_uri as _ws_parse_uri

    _HAS_MODERN_WS = True
except ImportError:  # pragma: no cover - websockets 12.x fallback
    _ws_connect_modern = None  # type: ignore[assignment]
    _ws_parse_uri = None  # type: ignore[assignment]
    _HAS_MODERN_WS = False


ConnectCallback = Callable[[RegisterResponse], None]
DisconnectCallback = Callable[[str], None]
ReconnectCallback = Callable[[int, float, str], None]
ErrorCallback = Callable[[Exception], None]
WarnCallback = Callable[[str], None]
DohOption = Optional[Union[bool, str, Sequence[str]]]


def _extract_http_status_and_body(exc: BaseException) -> Tuple[Optional[int], Optional[bytes]]:
    # websockets >= 13: InvalidStatus(response=Response(status_code=..., body=...))
    response = getattr(exc, "response", None)
    if response is not None:
        status_code = getattr(response, "status_code", None)
        body = getattr(response, "body", None)
        if isinstance(status_code, int):
            return status_code, body if isinstance(body, (bytes, bytearray)) else None
    # websockets 12.x legacy: InvalidStatusCode(status_code=...)
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        return status_code, None
    return None, None


if _HAS_MODERN_WS and _ws_connect_modern is not None:

    class _StealthWebSocketConnect(_ws_connect_modern):  # type: ignore[valid-type, misc]
        """``websockets.asyncio.client.connect`` subclass supporting DoH sockets,
        TRUE TLS 1.3 ECH (with 1-shot ``retry_configs`` retry), ClientHello TCP fragmentation,
        and pre-HTTP RFC 6125 certificate verification.
        """

        def __init__(
            self,
            uri: str,
            *,
            sock_factory: Callable[[], Awaitable[Tuple[socket.socket, str]]],
            tls_plan: TlsStealthPlan,
            ssl_context: Optional[ssl.SSLContext],
            base_ssl_context: Optional[ssl.SSLContext],
            no_tls_verify: bool,
            handshake_timeout: float,
            doh_config: DohConfig,
            doh_result: Optional[DohResult],
            doh_fallback: bool,
            on_warn: Optional[WarnCallback] = None,
            preconnected_sock: Optional[socket.socket] = None,
            resolved_ip: Optional[str] = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(uri, **kwargs)
            self._sock_factory = sock_factory
            self._preconnected_sock: Optional[socket.socket] = preconnected_sock
            self._resolved_ip = resolved_ip
            self._tls_plan = tls_plan
            self._ssl_context = ssl_context
            self._base_ssl_context = base_ssl_context
            self._no_tls_verify = no_tls_verify
            self._handshake_timeout = handshake_timeout
            self._doh_config = doh_config
            self._doh_result = doh_result
            self._doh_fallback = doh_fallback
            self._on_warn = on_warn
            self.transport_info: Optional[TransportInfo] = None

        def close_unused_socket(self) -> None:
            sock = self._preconnected_sock
            self._preconnected_sock = None
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

        async def _take_or_dial_socket(self) -> Tuple[socket.socket, str]:
            sock = self._preconnected_sock
            ip = self._resolved_ip
            self._preconnected_sock = None
            self._resolved_ip = None
            if sock is not None:
                return sock, ip or ""
            return await self._sock_factory()

        async def create_connection(self) -> Any:
            assert _ws_parse_uri is not None
            loop = asyncio.get_running_loop()
            ws_uri = _ws_parse_uri(self.uri)
            connection = self.protocol_factory(ws_uri)

            fragmented = False
            fragment_count = 0
            tls_version: Optional[str] = None
            effective_mode = self._tls_plan.effective_sni_mode
            wire_sni = self._tls_plan.wire_sni
            ech_status = "none"
            outer_sni: Optional[str] = None
            ech_retried = False
            resolved_ip = self._resolved_ip

            ech_available = bool(
                self._tls_plan.ech_config_list
                or (self._doh_result and self._doh_result.ech_configs)
            )
            ech_pub = (
                select_ech_public_name(self._tls_plan.ech_config_list)
                or parse_ech_public_name(self._tls_plan.ech_config_list)
                if self._tls_plan.ech_config_list
                else (
                    parse_ech_public_name(self._doh_result.ech_configs[0])
                    if self._doh_result and self._doh_result.ech_configs
                    else None
                )
            )

            if ws_uri.secure and self._tls_plan.use_ech and self._tls_plan.ech_config_list:
                initial_pair: Optional[Tuple[socket.socket, str]] = None
                if self._preconnected_sock is not None:
                    initial_pair = (self._preconnected_sock, self._resolved_ip or "")
                    self._preconnected_sock = None
                    self._resolved_ip = None
                try:
                    ech_res = await connect_tls13_ech(
                        sock_factory=self._sock_factory,
                        real_host=self._tls_plan.real_host,
                        ech_config_list=self._tls_plan.ech_config_list,
                        protocol=connection,
                        no_tls_verify=self._no_tls_verify,
                        base_ssl_context=self._base_ssl_context,
                        handshake_timeout=self._handshake_timeout,
                        alpn_protocols=("http/1.1",),
                        call_connection_made=True,
                        on_warn=self._on_warn,
                        initial_sock=initial_pair,
                    )
                    tls_version = ech_res.tls_version
                    effective_mode = "ech"
                    ech_status = ech_res.ech_status
                    outer_sni = ech_res.outer_sni
                    wire_sni = ech_res.outer_sni
                    ech_pub = ech_res.outer_sni
                    ech_retried = ech_res.retried
                    resolved_ip = ech_res.resolved_ip or resolved_ip
                except (EchConfigError, EchRejectedError) as exc:
                    if not self._tls_plan.allow_ech_fallback:
                        raise TunnelError(str(exc)) from exc
                    warn_msg = (
                        f"ECH unavailable ({exc}); falling back to ClientHello TCP fragmentation."
                    )
                    logger.warning("%s", warn_msg)
                    if self._on_warn is not None:
                        try:
                            self._on_warn(warn_msg)
                        except Exception:
                            pass
                    fb_plan = resolve_tls_plan(
                        is_tls=True,
                        real_host=self._tls_plan.real_host,
                        sni_mode="fragment",
                        no_tls_verify=self._no_tls_verify,
                    )
                    fb_ssl = build_stealth_ssl_context(
                        fb_plan,
                        no_tls_verify=self._no_tls_verify,
                        base_ssl_context=self._base_ssl_context,
                    )
                    raw_sock, resolved_ip = await self._sock_factory()
                    (
                        _tls_transport,
                        fragmented,
                        fragment_count,
                        tls_version,
                    ) = await upgrade_transport_tls(
                        raw_sock,
                        connection,
                        fb_plan,
                        ssl_context=fb_ssl,
                        handshake_timeout=self._handshake_timeout,
                        call_connection_made=True,
                    )
                    effective_mode = "fragment"
                    wire_sni = fb_plan.wire_sni
                    ech_status = "fallback"
                    outer_sni = None
            elif ws_uri.secure:
                assert self._ssl_context is not None
                raw_sock, resolved_ip = await self._take_or_dial_socket()
                (
                    _tls_transport,
                    fragmented,
                    fragment_count,
                    tls_version,
                ) = await upgrade_transport_tls(
                    raw_sock,
                    connection,
                    self._tls_plan,
                    ssl_context=self._ssl_context,
                    handshake_timeout=self._handshake_timeout,
                    call_connection_made=True,
                )
            else:
                raw_sock, resolved_ip = await self._take_or_dial_socket()
                try:
                    _, connection = await loop.create_connection(
                        lambda: connection,
                        sock=raw_sock,
                    )
                except BaseException:
                    try:
                        raw_sock.close()
                    except OSError:
                        pass
                    raise

            self.transport_info = TransportInfo(
                doh_mode=self._doh_config.mode,
                doh_used=bool(self._doh_result and self._doh_result.used_doh),
                doh_endpoint=self._doh_result.endpoint if self._doh_result else None,
                doh_fallback=self._doh_fallback,
                resolved_ip=resolved_ip,
                sni_mode=self._tls_plan.configured_sni_mode,
                effective_sni_mode=effective_mode,
                wire_sni=wire_sni,
                fragmented=fragmented,
                fragment_count=fragment_count,
                tls_version=tls_version,
                ech_available=ech_available,
                ech_public_name=ech_pub,
                ech_status=ech_status,
                outer_sni=outer_sni,
                ech_retried=ech_retried,
            )
            return connection


async def _open_websocket(
    ws_url: str,
    *,
    token: Optional[str],
    no_tls_verify: bool,
    doh_config: Optional[DohConfig] = None,
    sni_mode: str = "auto",
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
    open_timeout: float = 10.0,
    ping_interval: Optional[float] = 20.0,
    ping_timeout: Optional[float] = 20.0,
    doh_timeout: float = 3.0,
    doh_ssl_context: Optional[ssl.SSLContext] = None,
    base_ssl_context: Optional[ssl.SSLContext] = None,
    on_warn: Optional[WarnCallback] = None,
) -> Tuple[Any, TransportInfo]:
    parsed = urlsplit(ws_url)
    is_tls = parsed.scheme.lower() == "wss"
    host = parsed.hostname or ""
    port = parsed.port if parsed.port is not None else (443 if is_tls else 80)

    effective_doh = doh_config if doh_config is not None else DohConfig()

    # Validate SNI mode and explicit base64 --ech-config early (fail fast before network I/O).
    mode = normalize_sni_mode(sni_mode)
    explicit_ech_bytes = decode_ech_config_option(ech_config)

    if mode == "ech":
        if not is_tls:
            raise TunnelError("ECH mode (sni_mode='ech') requires a wss:// (HTTPS) server URL.")
        if explicit_ech_bytes is None and (effective_doh.mode == "off" or should_skip_doh(host)):
            raise TunnelError(
                f"ECH mode (sni_mode='ech') requires an ECHConfigList, but none was provided "
                f"via --ech-config and DoH is disabled or skipped for {host!r}"
            )

    if not _HAS_MODERN_WS and is_tls and (
        mode == "ech"
        or explicit_ech_bytes is not None
        or (not no_tls_verify and (mode == "none" or (sni is not None and sni.strip())))
    ):
        raise TunnelError(
            "TLS 1.3 ECH, omitted SNI (`sni_mode='none'`), and custom `--sni` with TLS verification "
            "require `websockets>=13.0` so handshake/certificate verification completes "
            "before sending HTTP upgrade headers/tokens. Upgrade `websockets` (`pip install -U websockets`)."
        )

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    kwargs: Dict[str, Any] = {
        "compression": None,
        "max_size": None,
        "open_timeout": open_timeout,
        "ping_interval": ping_interval,
        "ping_timeout": ping_timeout,
        "close_timeout": 5.0,
    }

    ips, doh_result, doh_fallback = await resolve_target_ips(
        host,
        effective_doh,
        doh_timeout=doh_timeout,
        doh_ssl_context=doh_ssl_context,
        on_warn=on_warn,
    )

    doh_ech_bytes = doh_result.ech_config_list if doh_result is not None else None
    available_ech_bytes = explicit_ech_bytes if explicit_ech_bytes is not None else doh_ech_bytes

    plan = resolve_tls_plan(
        is_tls=is_tls,
        real_host=host,
        sni_mode=mode,
        custom_sni=sni,
        no_tls_verify=no_tls_verify,
        ech_config_list=available_ech_bytes,
        explicit_ech=explicit_ech_bytes is not None,
    )
    if not _HAS_MODERN_WS:
        if plan.use_ech and plan.allow_ech_fallback:
            warn_msg = (
                "TLS 1.3 ECH requires websockets>=13.0; falling back to standard TLS on websockets 12.x."
            )
            logger.warning("%s", warn_msg)
            if on_warn is not None:
                try:
                    on_warn(warn_msg)
                except Exception:
                    pass
            plan = resolve_tls_plan(
                is_tls=is_tls,
                real_host=host,
                sni_mode="plain",
                custom_sni=sni,
                no_tls_verify=no_tls_verify,
            )
        elif plan.use_ech or plan.verify_real_host_manually:
            raise TunnelError(
                "TLS 1.3 ECH, omitted SNI (`sni_mode='none'`), and custom `--sni` with TLS verification "
                "require `websockets>=13.0` so handshake/certificate verification completes "
                "before sending HTTP upgrade headers/tokens. Upgrade `websockets` (`pip install -U websockets`)."
            )

    need_stealth_socket = (ips is not None) or (
        plan.use_tls and (plan.use_ech or plan.fragment_client_hello or plan.verify_real_host_manually)
    )

    ssl_ctx: Optional[ssl.SSLContext] = None
    if plan.use_tls and not plan.use_ech:
        ssl_ctx = build_stealth_ssl_context(
            plan,
            no_tls_verify=no_tls_verify,
            base_ssl_context=base_ssl_context,
        )

    connector: Optional[Any] = None
    try:
        if _HAS_MODERN_WS and _ws_connect_modern is not None:
            if headers:
                kwargs["additional_headers"] = headers

            if need_stealth_socket:

                async def _dial_tcp() -> Tuple[socket.socket, str]:
                    if ips is not None:
                        return await connect_tcp_socket(ips, port, timeout=open_timeout)
                    return await connect_system_tcp_socket(host, port, timeout=open_timeout)

                connector = _StealthWebSocketConnect(
                    ws_url,
                    sock_factory=_dial_tcp,
                    tls_plan=plan,
                    ssl_context=ssl_ctx,
                    base_ssl_context=base_ssl_context,
                    no_tls_verify=no_tls_verify,
                    handshake_timeout=open_timeout,
                    doh_config=effective_doh,
                    doh_result=doh_result,
                    doh_fallback=doh_fallback,
                    on_warn=on_warn,
                    **kwargs,
                )
                try:
                    ws = await connector
                finally:
                    connector.close_unused_socket()

                info = connector.transport_info or TransportInfo(
                    doh_mode=effective_doh.mode,
                    doh_used=bool(doh_result and doh_result.used_doh),
                    doh_endpoint=doh_result.endpoint if doh_result else None,
                    doh_fallback=doh_fallback,
                    resolved_ip=None,
                    sni_mode=plan.configured_sni_mode,
                    effective_sni_mode=plan.effective_sni_mode,
                    wire_sni=plan.wire_sni,
                    fragmented=False,
                    fragment_count=0,
                    tls_version=None,
                )
                return ws, info

            # Standard direct connection (ws:// or local plain wss:// without DoH)
            if plan.use_tls:
                kwargs["ssl"] = ssl_ctx if ssl_ctx is not None else build_ssl_context(no_tls_verify=no_tls_verify)
                kwargs["server_hostname"] = plan.wire_sni
            ws = await _ws_connect_modern(ws_url, **kwargs)
            tls_version: Optional[str] = None
            peer_ip: Optional[str] = None
            transport = getattr(ws, "transport", None)
            if transport is not None:
                ssl_obj = transport.get_extra_info("ssl_object")
                if ssl_obj is not None:
                    tls_version = ssl_obj.version()
                peername = transport.get_extra_info("peername")
                if isinstance(peername, tuple) and peername:
                    peer_ip = str(peername[0])
            info = TransportInfo(
                doh_mode=effective_doh.mode,
                doh_used=False,
                doh_endpoint=None,
                doh_fallback=doh_fallback,
                resolved_ip=peer_ip,
                sni_mode=plan.configured_sni_mode,
                effective_sni_mode=plan.effective_sni_mode,
                wire_sni=plan.wire_sni,
                fragmented=False,
                fragment_count=0,
                tls_version=tls_version,
            )
            return ws, info
        else:  # pragma: no cover - websockets 12.x fallback
            if plan.use_ech or plan.verify_real_host_manually:
                raise TunnelError(
                    "TLS 1.3 ECH, omitted SNI (`sni_mode='none'`), and custom `--sni` with TLS verification "
                    "require `websockets>=13.0` so handshake/certificate verification completes "
                    "before sending HTTP upgrade headers/tokens. Upgrade `websockets` (`pip install -U websockets`)."
                )
            if headers:
                kwargs["extra_headers"] = headers
            raw_sock_legacy: Optional[socket.socket] = None
            resolved_ip_legacy: Optional[str] = None
            if ips is not None:
                raw_sock_legacy, resolved_ip_legacy = await connect_tcp_socket(
                    ips,
                    port,
                    timeout=open_timeout,
                )
                kwargs["sock"] = raw_sock_legacy
            if plan.use_tls:
                kwargs["ssl"] = ssl_ctx if ssl_ctx is not None else build_ssl_context(no_tls_verify=no_tls_verify)
                kwargs["server_hostname"] = plan.wire_sni
            try:
                ws = await websockets.connect(ws_url, **kwargs)  # type: ignore[attr-defined]
            except BaseException:
                if raw_sock_legacy is not None:
                    try:
                        raw_sock_legacy.close()
                    except OSError:
                        pass
                raise
            info = TransportInfo(
                doh_mode=effective_doh.mode,
                doh_used=bool(doh_result and doh_result.used_doh),
                doh_endpoint=doh_result.endpoint if doh_result else None,
                doh_fallback=doh_fallback,
                resolved_ip=resolved_ip_legacy,
                sni_mode=plan.configured_sni_mode,
                effective_sni_mode=plan.effective_sni_mode,
                wire_sni=plan.wire_sni,
                fragmented=False,
                fragment_count=0,
                tls_version=None,
            )
            return ws, info
    except (AuthError, TunnelConnectionError, TunnelError):
        raise
    except Exception as exc:
        status_code, body = _extract_http_status_and_body(exc)
        if status_code == 401:
            msg, server_msg = format_401_error(body, had_token=bool(token))
            tinfo = getattr(connector, "transport_info", None) if connector is not None else None
            raise AuthError(
                msg,
                status_code=401,
                server_message=server_msg,
                transport_info=tinfo,
            ) from exc
        raise TunnelConnectionError(f"connect failed: {exc}") from exc


async def _perform_registration(
    ws: Any,
    *,
    prefix: Optional[str],
    target_url: str,
    ever_connected: bool,
    timeout: float = 10.0,
) -> RegisterResponse:
    reg_req = RegisterRequest(
        prefix=prefix,
        target_url=target_url,
        client_version=__version__,
    )
    try:
        await ws.send(reg_req.to_json())
    except Exception as exc:
        raise TunnelConnectionError(f"failed sending registration: {exc}") from exc

    async def _recv_reply() -> RegisterResponse:
        while True:
            msg = await ws.recv()
            if isinstance(msg, str):
                try:
                    return RegisterResponse.from_json(msg)
                except ValueError as exc:
                    raise TunnelConnectionError(
                        f"invalid server response JSON: {exc}"
                    ) from exc

    try:
        resp = await asyncio.wait_for(_recv_reply(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise TunnelConnectionError("registration timed out") from exc
    except TunnelConnectionError:
        raise
    except Exception as exc:
        raise TunnelConnectionError(f"connection closed before registration reply: {exc}") from exc

    if not resp.ok:
        err_msg = resp.error or "registration rejected by server"
        non_retryable = (not ever_connected) or is_non_retryable_rejection(err_msg)
        raise RegistrationError(
            f"Registration rejected: {err_msg}"
            if non_retryable
            else f"re-registration rejected: {err_msg}",
            retryable=not non_retryable,
        )

    return resp


class Tunnel:
    """Active async Neruton tunnel forwarding traffic to a local HTTP/WebSocket service."""

    def __init__(
        self,
        *,
        target_url: str,
        server: str,
        token: Optional[str] = None,
        subdomain: Optional[str] = None,
        no_tls_verify: bool = False,
        host_header: Optional[str] = None,
        doh: DohOption = None,
        sni_mode: Optional[str] = None,
        sni: Optional[str] = None,
        ech_config: Optional[str] = None,
        config_file: Optional[Union[str, Path]] = None,
        reconnect: bool = True,
        retry_initial: bool = False,
        initial_backoff: float = 1.0,
        max_backoff: float = 30.0,
        handshake_timeout: float = 10.0,
        ping_interval: Optional[float] = 20.0,
        ping_timeout: Optional[float] = 20.0,
        on_connect: Optional[ConnectCallback] = None,
        on_disconnect: Optional[DisconnectCallback] = None,
        on_reconnect: Optional[ReconnectCallback] = None,
        on_request: Optional[RequestCallback] = None,
        on_error: Optional[ErrorCallback] = None,
        on_warn: Optional[WarnCallback] = None,
    ) -> None:
        self._normalized_target = normalize_target_url(target_url)
        self._ws_url = build_tunnel_ws_url(server)
        self._server_url = server
        self._token = token.strip() if token and token.strip() else None
        self._no_tls_verify = no_tls_verify
        self._reconnect = reconnect
        self._retry_initial = retry_initial
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._handshake_timeout = handshake_timeout
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout

        stealth = resolve_stealth_options(
            doh=doh,
            sni_mode=sni_mode,
            sni=sni,
            ech_config=ech_config,
            config_file=config_file,
        )
        self._doh_config = stealth.doh
        self._sni_mode = stealth.sni_mode
        self._sni = stealth.sni
        self._ech_config = stealth.ech_config
        self._transport_info: Optional[TransportInfo] = None

        if subdomain is not None and subdomain.strip():
            self._sticky_prefix: Optional[str] = validate_prefix(subdomain)
        else:
            self._sticky_prefix = None

        self._target_cfg = TargetConfig.from_url(
            self._normalized_target,
            host_header=host_header,
            no_tls_verify=no_tls_verify,
        )

        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._on_reconnect = on_reconnect
        self._on_request = on_request
        self._on_error = on_error
        self._on_warn = on_warn

        self._registration: Optional[RegisterResponse] = None
        self._session: Optional[YamuxSession] = None
        self._pending_ws: Optional[Any] = None
        self._runner_task: Optional[asyncio.Task[None]] = None
        self._connect_task: Optional[asyncio.Task[Tuple[Any, RegisterResponse, TransportInfo]]] = None
        self._stream_tasks: Set[asyncio.Task[None]] = set()
        self._stop_event: Optional[asyncio.Event] = None
        self._ever_connected = False
        self._connected = False
        self._closed = False
        self._fatal_error: Optional[Exception] = None

    @property
    def registration(self) -> Optional[RegisterResponse]:
        return self._registration

    @property
    def transport_info(self) -> Optional[TransportInfo]:
        return self._transport_info

    @property
    def doh_config(self) -> DohConfig:
        return self._doh_config

    @property
    def sni_mode(self) -> str:
        return self._sni_mode

    @property
    def sni(self) -> Optional[str]:
        return self._sni

    @property
    def ech_config(self) -> Optional[str]:
        return self._ech_config

    @property
    def public_url(self) -> str:
        return self._registration.public_url if self._registration else ""

    @property
    def preview_url(self) -> str:
        return self._registration.preview_url if self._registration else ""

    @property
    def path_url(self) -> str:
        return self._registration.path_url if self._registration else ""

    @property
    def dashboard_url(self) -> str:
        return self._registration.dashboard_url if self._registration else ""

    @property
    def prefix(self) -> str:
        return self._registration.prefix if self._registration else (self._sticky_prefix or "")

    @property
    def tunnel_id(self) -> str:
        return self._registration.tunnel_id if self._registration else ""

    @property
    def owner_username(self) -> Optional[str]:
        return self._registration.owner_username if self._registration else None

    @property
    def token_name(self) -> Optional[str]:
        return self._registration.token_name if self._registration else None

    @property
    def target_url(self) -> str:
        return self._normalized_target

    @property
    def server_url(self) -> str:
        return self._server_url

    @property
    def ws_url(self) -> str:
        return self._ws_url

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def closed(self) -> bool:
        return self._closed

    @staticmethod
    async def _safe_close_ws(ws: Any) -> None:
        try:
            await ws.close()
        except Exception:
            pass

    async def start(self) -> Tunnel:
        """Establish the initial tunnel connection and start forwarding inbound streams."""
        if self._runner_task is not None or self._closed:
            return self

        if self._stop_event is None:
            self._stop_event = asyncio.Event()
        backoff = self._initial_backoff
        attempt = 0

        while True:
            if self._closed:
                return self
            try:
                triple = await self._connect_and_register_cancellable()
                if triple is None:
                    self._closed = True
                    return self
                ws, reg, transport_info = triple
                break
            except (AuthError, RegistrationError) as exc:
                if isinstance(exc, RegistrationError) and exc.retryable and self._retry_initial:
                    reason = str(exc)
                else:
                    self._closed = True
                    self._fatal_error = exc
                    raise
            except TunnelConnectionError as exc:
                if not self._retry_initial:
                    self._closed = True
                    self._fatal_error = exc
                    raise
                reason = str(exc)
            except TunnelError as exc:
                # Non-retryable configuration/capability error (e.g. sni_mode="ech").
                self._closed = True
                self._fatal_error = exc
                raise

            attempt += 1
            self._safe_callback(self._on_reconnect, attempt, backoff, reason)
            if await self._sleep_or_stop(backoff):
                self._closed = True
                return self
            backoff = min(backoff * 2.0, self._max_backoff)

        if self._closed:
            await self._safe_close_ws(ws)
            return self

        self._transport_info = transport_info
        self._apply_registration(reg)
        session = self._spawn_session(ws)
        self._runner_task = asyncio.create_task(
            self._run_loop(session, time.monotonic()),
            name=f"neruton-tunnel-{self.prefix}",
        )
        return self

    async def _connect_and_register_cancellable(
        self,
    ) -> Optional[Tuple[Any, RegisterResponse, TransportInfo]]:
        if self._closed:
            return None
        if self._stop_event is None:
            self._stop_event = asyncio.Event()

        connect_task: asyncio.Task[Tuple[Any, RegisterResponse, TransportInfo]] = asyncio.create_task(
            self._connect_and_register(),
            name="neruton-connect",
        )
        self._connect_task = connect_task
        stop_waiter = asyncio.create_task(self._stop_event.wait(), name="neruton-stop-wait")
        try:
            done, _ = await asyncio.wait(
                {connect_task, stop_waiter},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if connect_task in done:
                if connect_task.cancelled():
                    return None
                ws, reg, info = connect_task.result()
                if self._closed:
                    await self._safe_close_ws(ws)
                    return None
                return ws, reg, info

            # close() fired while connect/registration was still in flight.
            connect_task.cancel()
            try:
                ws, _, _ = await connect_task
            except BaseException:
                return None
            await self._safe_close_ws(ws)
            return None
        finally:
            if not stop_waiter.done():
                stop_waiter.cancel()
                try:
                    await stop_waiter
                except (asyncio.CancelledError, Exception):
                    pass
            if not connect_task.done():
                connect_task.cancel()
                try:
                    ws, _, _ = await connect_task
                except BaseException:
                    pass
                else:
                    await self._safe_close_ws(ws)
            if self._connect_task is connect_task:
                self._connect_task = None

    async def _connect_and_register(self) -> Tuple[Any, RegisterResponse, TransportInfo]:
        ws, info = await _open_websocket(
            self._ws_url,
            token=self._token,
            no_tls_verify=self._no_tls_verify,
            doh_config=self._doh_config,
            sni_mode=self._sni_mode,
            sni=self._sni,
            ech_config=self._ech_config,
            open_timeout=self._handshake_timeout,
            ping_interval=self._ping_interval,
            ping_timeout=self._ping_timeout,
            on_warn=self._on_warn,
        )
        self._pending_ws = ws
        try:
            if self._closed:
                raise asyncio.CancelledError()
            reg = await _perform_registration(
                ws,
                prefix=self._sticky_prefix,
                target_url=self._normalized_target,
                ever_connected=self._ever_connected,
                timeout=self._handshake_timeout,
            )
            logger.info("Connected tunnel via %s", info.summary())
            return ws, reg, info
        except BaseException:
            if self._pending_ws is ws:
                self._pending_ws = None
            await self._safe_close_ws(ws)
            raise

    def _apply_registration(self, reg: RegisterResponse) -> None:
        self._registration = reg
        self._sticky_prefix = reg.prefix
        self._ever_connected = True
        self._connected = True
        self._safe_callback(self._on_connect, reg)

    def _spawn_session(self, ws: Any) -> YamuxSession:
        if self._pending_ws is ws:
            self._pending_ws = None
        transport = WsByteTransport(ws)
        session = YamuxSession(transport, Mode.SERVER).start()
        self._session = session
        return session

    async def _serve_session(self, session: YamuxSession) -> str:
        try:
            while not self._closed:
                stream = await session.accept()
                if stream is None:
                    break
                task = asyncio.create_task(
                    handle_yamux_stream(
                        stream,
                        self._target_cfg,
                        on_request=self._on_request,
                    ),
                    name=f"neruton-stream-{stream.stream_id}",
                )
                self._stream_tasks.add(task)
                task.add_done_callback(self._stream_tasks.discard)
        finally:
            self._connected = False
            await session.close(GoAwayCode.NORMAL)
            if self._session is session:
                self._session = None

        if session.error is not None:
            return f"tunnel stream closed: {session.error}"
        return "tunnel stream closed by server"

    async def _run_loop(self, initial_session: YamuxSession, connected_at: float) -> None:
        session: Optional[YamuxSession] = initial_session
        backoff = self._initial_backoff
        attempt = 0
        reason = "connection failed"

        try:
            while not self._closed:
                if session is not None:
                    reason = await self._serve_session(session)
                    session = None
                    if self._closed:
                        return
                    self._safe_callback(self._on_disconnect, reason)
                    if not self._reconnect:
                        return
                    if time.monotonic() - connected_at >= 10.0:
                        backoff = self._initial_backoff
                        attempt = 0

                attempt += 1
                self._safe_callback(self._on_reconnect, attempt, backoff, reason)
                if await self._sleep_or_stop(backoff):
                    return
                backoff = min(backoff * 2.0, self._max_backoff)

                try:
                    connected_at = time.monotonic()
                    triple = await self._connect_and_register_cancellable()
                except AuthError as exc:
                    self._fatal_error = exc
                    self._safe_callback(self._on_error, exc)
                    return
                except RegistrationError as exc:
                    if not exc.retryable:
                        self._fatal_error = exc
                        self._safe_callback(self._on_error, exc)
                        return
                    reason = str(exc)
                    self._safe_callback(self._on_disconnect, reason)
                    continue
                except TunnelConnectionError as exc:
                    reason = str(exc)
                    self._safe_callback(self._on_disconnect, reason)
                    continue
                except TunnelError as exc:
                    self._fatal_error = exc
                    self._safe_callback(self._on_error, exc)
                    return

                if triple is None:
                    return
                ws, reg, transport_info = triple
                if self._closed:
                    await self._safe_close_ws(ws)
                    return

                self._transport_info = transport_info
                self._apply_registration(reg)
                session = self._spawn_session(ws)
        except asyncio.CancelledError:
            return
        finally:
            if session is not None:
                try:
                    await session.close(GoAwayCode.NORMAL)
                except Exception:
                    pass
                if self._session is session:
                    self._session = None
            self._connected = False
            self._closed = True

    async def _sleep_or_stop(self, seconds: float) -> bool:
        if self._stop_event is None or self._stop_event.is_set():
            return True
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
            return True
        except asyncio.TimeoutError:
            return self._closed

    @staticmethod
    def _safe_callback(cb: Optional[Callable[..., Any]], *args: Any) -> None:
        if cb is None:
            return
        try:
            cb(*args)
        except Exception:
            pass

    async def wait(self) -> None:
        """Wait until the tunnel closes. Re-raises fatal errors (such as revoked token 401)."""
        if self._runner_task is not None:
            await self._runner_task
        if self._fatal_error is not None:
            raise self._fatal_error

    async def close(self) -> None:
        """Gracefully shut down the tunnel, sending Yamux GoAway and closing the WebSocket."""
        if (
            self._closed
            and self._runner_task is None
            and self._connect_task is None
            and self._pending_ws is None
            and self._session is None
        ):
            return
        self._closed = True
        self._connected = False
        if self._stop_event is not None:
            self._stop_event.set()

        connect_task = self._connect_task
        if connect_task is not None and not connect_task.done():
            connect_task.cancel()
            try:
                await asyncio.wait_for(asyncio.shield(connect_task), timeout=2.0)
            except BaseException:
                pass

        pending_ws = self._pending_ws
        if pending_ws is not None:
            self._pending_ws = None
            await self._safe_close_ws(pending_ws)

        session = self._session
        if session is not None:
            try:
                await session.close(GoAwayCode.NORMAL)
            except Exception:
                pass

        for task in list(self._stream_tasks):
            if not task.done():
                task.cancel()
        if self._stream_tasks:
            await asyncio.gather(*list(self._stream_tasks), return_exceptions=True)
            self._stream_tasks.clear()

        runner = self._runner_task
        if runner is not None and not runner.done():
            try:
                await asyncio.wait_for(runner, timeout=2.0)
            except asyncio.TimeoutError:
                runner.cancel()
                try:
                    await runner
                except (asyncio.CancelledError, Exception):
                    pass

    async def __aenter__(self) -> Tunnel:
        if self._runner_task is None:
            await self.start()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()


class _TunnelConnectContext:
    """Dual awaitable + async context manager returned by `neruton.connect()`/`forward()`/`http()`.

    Supports both:
        async with neruton.connect("http://127.0.0.1:3000") as tunnel:
            ...
    and:
        tunnel = await neruton.connect("http://127.0.0.1:3000")
    """

    def __init__(self, tunnel: Tunnel) -> None:
        self._tunnel = tunnel

    def __await__(self) -> Generator[Any, None, Tunnel]:
        return self._tunnel.start().__await__()

    async def __aenter__(self) -> Tunnel:
        return await self._tunnel.start()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self._tunnel.close()


def _resolve_target_arg(
    target: Optional[Union[int, str]],
    url: Optional[str],
) -> str:
    if target is not None and url is not None:
        raise ValueError("pass either positional target/port or keyword 'url', not both")
    if url is not None:
        return url
    if target is not None:
        return str(target)
    raise ValueError("a local target port or URL is required")


def _build_tunnel(
    target: Optional[Union[int, str]] = None,
    *,
    url: Optional[str] = None,
    server: Optional[str] = None,
    token: Optional[str] = None,
    subdomain: Optional[str] = None,
    no_tls_verify: bool = False,
    host_header: Optional[str] = None,
    doh: DohOption = None,
    sni_mode: Optional[str] = None,
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
    config_file: Optional[Union[str, Path]] = None,
    reconnect: bool = True,
    retry_initial: bool = False,
    initial_backoff: float = 1.0,
    max_backoff: float = 30.0,
    handshake_timeout: float = 10.0,
    ping_interval: Optional[float] = 20.0,
    ping_timeout: Optional[float] = 20.0,
    on_connect: Optional[ConnectCallback] = None,
    on_disconnect: Optional[DisconnectCallback] = None,
    on_reconnect: Optional[ReconnectCallback] = None,
    on_request: Optional[RequestCallback] = None,
    on_error: Optional[ErrorCallback] = None,
    on_warn: Optional[WarnCallback] = None,
) -> Tunnel:
    target_str = _resolve_target_arg(target, url)
    resolved_server, resolved_token = resolve_server_and_token(
        server=server,
        token=token,
        config_file=config_file,
    )
    return Tunnel(
        target_url=target_str,
        server=resolved_server,
        token=resolved_token,
        subdomain=subdomain,
        no_tls_verify=no_tls_verify,
        host_header=host_header,
        doh=doh,
        sni_mode=sni_mode,
        sni=sni,
        ech_config=ech_config,
        config_file=config_file,
        reconnect=reconnect,
        retry_initial=retry_initial,
        initial_backoff=initial_backoff,
        max_backoff=max_backoff,
        handshake_timeout=handshake_timeout,
        ping_interval=ping_interval,
        ping_timeout=ping_timeout,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_reconnect=on_reconnect,
        on_request=on_request,
        on_error=on_error,
        on_warn=on_warn,
    )


def connect(
    target: Optional[Union[int, str]] = None,
    *,
    url: Optional[str] = None,
    server: Optional[str] = None,
    token: Optional[str] = None,
    subdomain: Optional[str] = None,
    no_tls_verify: bool = False,
    host_header: Optional[str] = None,
    doh: DohOption = None,
    sni_mode: Optional[str] = None,
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
    config_file: Optional[Union[str, Path]] = None,
    reconnect: bool = True,
    retry_initial: bool = False,
    initial_backoff: float = 1.0,
    max_backoff: float = 30.0,
    handshake_timeout: float = 10.0,
    ping_interval: Optional[float] = 20.0,
    ping_timeout: Optional[float] = 20.0,
    on_connect: Optional[ConnectCallback] = None,
    on_disconnect: Optional[DisconnectCallback] = None,
    on_reconnect: Optional[ReconnectCallback] = None,
    on_request: Optional[RequestCallback] = None,
    on_error: Optional[ErrorCallback] = None,
    on_warn: Optional[WarnCallback] = None,
) -> _TunnelConnectContext:
    """Connect an async Neruton tunnel.

    Can be awaited directly (`tunnel = await neruton.connect(...)`) or used as an
    async context manager (`async with neruton.connect(...) as tunnel:`).
    """
    tunnel = _build_tunnel(
        target,
        url=url,
        server=server,
        token=token,
        subdomain=subdomain,
        no_tls_verify=no_tls_verify,
        host_header=host_header,
        doh=doh,
        sni_mode=sni_mode,
        sni=sni,
        ech_config=ech_config,
        config_file=config_file,
        reconnect=reconnect,
        retry_initial=retry_initial,
        initial_backoff=initial_backoff,
        max_backoff=max_backoff,
        handshake_timeout=handshake_timeout,
        ping_interval=ping_interval,
        ping_timeout=ping_timeout,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_reconnect=on_reconnect,
        on_request=on_request,
        on_error=on_error,
        on_warn=on_warn,
    )
    return _TunnelConnectContext(tunnel)


def forward(
    port_or_url: Union[int, str],
    *,
    server: Optional[str] = None,
    token: Optional[str] = None,
    subdomain: Optional[str] = None,
    no_tls_verify: bool = False,
    host_header: Optional[str] = None,
    doh: DohOption = None,
    sni_mode: Optional[str] = None,
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
    config_file: Optional[Union[str, Path]] = None,
    reconnect: bool = True,
    retry_initial: bool = False,
    on_connect: Optional[ConnectCallback] = None,
    on_disconnect: Optional[DisconnectCallback] = None,
    on_reconnect: Optional[ReconnectCallback] = None,
    on_request: Optional[RequestCallback] = None,
    on_error: Optional[ErrorCallback] = None,
    on_warn: Optional[WarnCallback] = None,
) -> _TunnelConnectContext:
    """Shorthand async API for forwarding a local port or URL (e.g. `neruton.forward(3000)`)."""
    return connect(
        port_or_url,
        server=server,
        token=token,
        subdomain=subdomain,
        no_tls_verify=no_tls_verify,
        host_header=host_header,
        doh=doh,
        sni_mode=sni_mode,
        sni=sni,
        ech_config=ech_config,
        config_file=config_file,
        reconnect=reconnect,
        retry_initial=retry_initial,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_reconnect=on_reconnect,
        on_request=on_request,
        on_error=on_error,
        on_warn=on_warn,
    )


def http(
    port_or_url: Union[int, str],
    *,
    server: Optional[str] = None,
    token: Optional[str] = None,
    subdomain: Optional[str] = None,
    no_tls_verify: bool = False,
    host_header: Optional[str] = None,
    doh: DohOption = None,
    sni_mode: Optional[str] = None,
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
    config_file: Optional[Union[str, Path]] = None,
    reconnect: bool = True,
    retry_initial: bool = False,
    on_connect: Optional[ConnectCallback] = None,
    on_disconnect: Optional[DisconnectCallback] = None,
    on_reconnect: Optional[ReconnectCallback] = None,
    on_request: Optional[RequestCallback] = None,
    on_error: Optional[ErrorCallback] = None,
    on_warn: Optional[WarnCallback] = None,
) -> _TunnelConnectContext:
    """Alias for `neruton.forward(port_or_url, ...)` mirroring `neruton http <port>`."""
    return forward(
        port_or_url,
        server=server,
        token=token,
        subdomain=subdomain,
        no_tls_verify=no_tls_verify,
        host_header=host_header,
        doh=doh,
        sni_mode=sni_mode,
        sni=sni,
        ech_config=ech_config,
        config_file=config_file,
        reconnect=reconnect,
        retry_initial=retry_initial,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_reconnect=on_reconnect,
        on_request=on_request,
        on_error=on_error,
        on_warn=on_warn,
    )


class SyncTunnel:
    """Synchronous Neruton tunnel backed by a dedicated daemon event-loop thread.

    Designed for Flask, Django, FastAPI scripts, notebooks, and synchronous CLIs.
    """

    def __init__(self, tunnel: Tunnel) -> None:
        self._tunnel = tunnel
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._closed_lock = threading.Lock()
        self._closed = False

        self._thread = threading.Thread(
            target=self._run_loop_thread,
            name="neruton-sync-tunnel",
            daemon=True,
        )
        self._thread.start()
        self._ready.wait()

        try:
            fut = asyncio.run_coroutine_threadsafe(self._tunnel.start(), self._loop)
            fut.result()
        except Exception:
            self._shutdown_loop()
            raise

    def _run_loop_thread(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            pending = asyncio.all_tasks(self._loop)
            for task in pending:
                task.cancel()
            if pending:
                self._loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True)
                )
            self._loop.close()

    def _shutdown_loop(self) -> None:
        if not self._loop.is_closed():
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except RuntimeError:
                pass
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=5.0)

    @property
    def transport_info(self) -> Optional[TransportInfo]:
        return self._tunnel.transport_info

    @property
    def public_url(self) -> str:
        return self._tunnel.public_url

    @property
    def preview_url(self) -> str:
        return self._tunnel.preview_url

    @property
    def path_url(self) -> str:
        return self._tunnel.path_url

    @property
    def dashboard_url(self) -> str:
        return self._tunnel.dashboard_url

    @property
    def prefix(self) -> str:
        return self._tunnel.prefix

    @property
    def tunnel_id(self) -> str:
        return self._tunnel.tunnel_id

    @property
    def owner_username(self) -> Optional[str]:
        return self._tunnel.owner_username

    @property
    def token_name(self) -> Optional[str]:
        return self._tunnel.token_name

    @property
    def target_url(self) -> str:
        return self._tunnel.target_url

    @property
    def server_url(self) -> str:
        return self._tunnel.server_url

    @property
    def connected(self) -> bool:
        return self._tunnel.connected

    @property
    def closed(self) -> bool:
        return self._closed or self._tunnel.closed

    def wait(self, timeout: Optional[float] = None) -> None:
        """Block until the tunnel closes or `timeout` seconds elapse."""
        if self._closed or self._loop.is_closed():
            return
        fut = asyncio.run_coroutine_threadsafe(self._tunnel.wait(), self._loop)
        try:
            fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            raise TimeoutError("timed out waiting for tunnel to close") from exc

    def close(self) -> None:
        """Close the tunnel and stop its background event loop thread (idempotent)."""
        with self._closed_lock:
            if self._closed:
                return
            self._closed = True

        if not self._loop.is_closed():
            try:
                fut = asyncio.run_coroutine_threadsafe(self._tunnel.close(), self._loop)
                fut.result(timeout=5.0)
            except Exception:
                pass
        self._shutdown_loop()

    def __enter__(self) -> SyncTunnel:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


def open_tunnel(
    target: Optional[Union[int, str]] = None,
    *,
    url: Optional[str] = None,
    server: Optional[str] = None,
    token: Optional[str] = None,
    subdomain: Optional[str] = None,
    no_tls_verify: bool = False,
    host_header: Optional[str] = None,
    doh: DohOption = None,
    sni_mode: Optional[str] = None,
    sni: Optional[str] = None,
    ech_config: Optional[str] = None,
    config_file: Optional[Union[str, Path]] = None,
    reconnect: bool = True,
    retry_initial: bool = False,
    initial_backoff: float = 1.0,
    max_backoff: float = 30.0,
    handshake_timeout: float = 10.0,
    ping_interval: Optional[float] = 20.0,
    ping_timeout: Optional[float] = 20.0,
    on_connect: Optional[ConnectCallback] = None,
    on_disconnect: Optional[DisconnectCallback] = None,
    on_reconnect: Optional[ReconnectCallback] = None,
    on_request: Optional[RequestCallback] = None,
    on_error: Optional[ErrorCallback] = None,
    on_warn: Optional[WarnCallback] = None,
) -> SyncTunnel:
    """Open a synchronous Neruton tunnel (runs an asyncio loop in a daemon thread).

    Usage:
        with neruton.open(3000, server="...", token="ntk_...") as tunnel:
            print(tunnel.public_url)
    """
    tunnel = _build_tunnel(
        target,
        url=url,
        server=server,
        token=token,
        subdomain=subdomain,
        no_tls_verify=no_tls_verify,
        host_header=host_header,
        doh=doh,
        sni_mode=sni_mode,
        sni=sni,
        ech_config=ech_config,
        config_file=config_file,
        reconnect=reconnect,
        retry_initial=retry_initial,
        initial_backoff=initial_backoff,
        max_backoff=max_backoff,
        handshake_timeout=handshake_timeout,
        ping_interval=ping_interval,
        ping_timeout=ping_timeout,
        on_connect=on_connect,
        on_disconnect=on_disconnect,
        on_reconnect=on_reconnect,
        on_request=on_request,
        on_error=on_error,
        on_warn=on_warn,
    )
    return SyncTunnel(tunnel)
