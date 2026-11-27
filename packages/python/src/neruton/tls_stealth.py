"""Stealth TLS transport for Neruton: DoH socket dialing, ClientHello TCP fragmentation,
omitted/custom SNI, and strict pure-Python RFC 6125 certificate hostname verification.
"""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from .doh import (
    DohConfig,
    DohResult,
    is_ip_literal,
    normalize_hostname,
    parse_ech_public_name,
    resolve_doh,
    should_skip_doh,
)
from .errors import DohError, TunnelConnectionError, TunnelError
from .hpke import decode_ech_config_list_base64, select_ech_public_name

logger = logging.getLogger("neruton.tls_stealth")

VALID_SNI_MODES: Tuple[str, ...] = ("auto", "ech", "fragment", "none", "plain")

_DEFAULT_FRAGMENT_DELAY = 0.002  # 2 ms between ClientHello TCP segments


@dataclass(frozen=True)
class TlsStealthPlan:
    """Resolved per-connection TLS stealth execution plan."""

    use_tls: bool
    real_host: str
    configured_sni_mode: str
    effective_sni_mode: str  # "ech" | "fragment" | "none" | "plain"
    wire_sni: Optional[str]  # server_hostname passed to SSLContext (or outer ECH public_name)
    fragment_client_hello: bool
    verify_real_host_manually: bool
    use_ech: bool = False
    ech_config_list: Optional[bytes] = None
    allow_ech_fallback: bool = False


@dataclass(frozen=True)
class TransportInfo:
    """Observable metadata describing the active stealth transport for a tunnel connection."""

    doh_mode: str
    doh_used: bool
    doh_endpoint: Optional[str]
    doh_fallback: bool
    resolved_ip: Optional[str]
    sni_mode: str
    effective_sni_mode: str
    wire_sni: Optional[str]
    fragmented: bool
    fragment_count: int
    tls_version: Optional[str]
    ech_available: bool = False
    ech_public_name: Optional[str] = None
    ech_status: str = "none"  # "accepted" | "fallback" | "none"
    outer_sni: Optional[str] = None
    ech_retried: bool = False

    def summary(self) -> str:
        parts: List[str] = []
        ep_label = urlsplit(self.doh_endpoint).hostname if self.doh_endpoint else "DoH"

        if self.ech_status == "accepted" and self.tls_version:
            outer = self.outer_sni or self.ech_public_name or self.wire_sni or "unknown"
            ech_label = (
                f"ECH (outer: {outer}, retried)" if self.ech_retried else f"ECH (outer: {outer})"
            )
            if self.doh_used:
                parts.append(f"DoH + {ech_label}")
                if self.resolved_ip:
                    parts.append(f"{ep_label} -> {self.resolved_ip}")
            elif self.doh_fallback:
                parts.append(f"system DNS (DoH fallback) + {ech_label}")
                if self.resolved_ip:
                    parts.append(self.resolved_ip)
            else:
                parts.append(f"direct DNS + {ech_label}")
                if self.resolved_ip:
                    parts.append(self.resolved_ip)
            parts.append(self.tls_version)
            return " | ".join(parts)

        if self.doh_used:
            ip_part = f" -> {self.resolved_ip}" if self.resolved_ip else ""
            parts.append(f"DoH ({ep_label}){ip_part}")
        elif self.doh_fallback:
            parts.append("system DNS (DoH fallback)")
        else:
            parts.append("direct DNS")

        if self.tls_version:
            parts.append(self.tls_version)
            if self.effective_sni_mode == "fragment":
                fb_note = ", ECH fallback" if self.ech_status == "fallback" else ""
                if self.wire_sni:
                    parts.append(
                        f"ClientHello fragmented ({self.fragment_count} segs, SNI: {self.wire_sni}{fb_note})"
                    )
                else:
                    parts.append(f"ClientHello fragmented ({self.fragment_count} segs{fb_note})")
            elif self.effective_sni_mode == "none":
                parts.append("SNI omitted (RFC 6125 cert check)")
            elif self.wire_sni:
                parts.append(f"SNI: {self.wire_sni}")
            else:
                parts.append("plain TLS")
        else:
            parts.append("ws://")

        return " | ".join(parts)

    def __str__(self) -> str:
        return self.summary()


def normalize_sni_mode(value: Optional[str]) -> str:
    """Validate and normalize an SNI mode string (defaulting to ``'auto'``)."""
    if value is None or not value.strip():
        return "auto"
    lower = value.strip().lower()
    if lower not in VALID_SNI_MODES:
        expected = ", ".join(VALID_SNI_MODES)
        raise ValueError(f"invalid sni_mode {value!r}: expected one of {expected}")
    return lower


def decode_ech_config_option(value: Optional[str]) -> Optional[bytes]:
    """Decode an optional base64-encoded ``ech_config`` option into raw ``ECHConfigList`` bytes."""
    if value is None or not value.strip():
        return None
    return decode_ech_config_list_base64(value)


def resolve_tls_plan(
    *,
    is_tls: bool,
    real_host: str,
    sni_mode: str,
    custom_sni: Optional[str] = None,
    no_tls_verify: bool = False,
    ech_config_list: Optional[bytes] = None,
    explicit_ech: bool = False,
) -> TlsStealthPlan:
    """Determine the concrete TLS/SNI strategy for a target connection."""
    mode = normalize_sni_mode(sni_mode)
    clean_host = normalize_hostname(real_host)
    normalized_sni = normalize_hostname(custom_sni) if custom_sni and custom_sni.strip() else ""
    clean_sni = normalized_sni or None

    if not is_tls:
        if mode == "ech":
            raise TunnelError(
                "ECH mode (sni_mode='ech') requires a wss:// (HTTPS) server URL."
            )
        return TlsStealthPlan(
            use_tls=False,
            real_host=clean_host,
            configured_sni_mode=mode,
            effective_sni_mode="plain",
            wire_sni=None,
            fragment_client_hello=False,
            verify_real_host_manually=False,
        )

    is_local_or_ip = should_skip_doh(clean_host)
    ech_outer = (
        select_ech_public_name(ech_config_list) or parse_ech_public_name(ech_config_list)
        if ech_config_list
        else None
    )

    if mode == "ech":
        if not ech_config_list:
            raise TunnelError(
                f"ECH mode (sni_mode='ech') requires an ECHConfigList, but none was provided "
                f"via --ech-config or DoH HTTPS record for {clean_host!r}"
            )
        return TlsStealthPlan(
            use_tls=True,
            real_host=clean_host,
            configured_sni_mode=mode,
            effective_sni_mode="ech",
            wire_sni=ech_outer,
            fragment_client_hello=False,
            verify_real_host_manually=False,
            use_ech=True,
            ech_config_list=ech_config_list,
            allow_ech_fallback=False,
        )

    if mode == "auto":
        if is_local_or_ip and clean_sni is None and not explicit_ech:
            return TlsStealthPlan(
                use_tls=True,
                real_host=clean_host,
                configured_sni_mode=mode,
                effective_sni_mode="plain",
                wire_sni=clean_host,
                fragment_client_hello=False,
                verify_real_host_manually=False,
            )
        if clean_sni is not None:
            return TlsStealthPlan(
                use_tls=True,
                real_host=clean_host,
                configured_sni_mode=mode,
                effective_sni_mode="fragment",
                wire_sni=clean_sni,
                fragment_client_hello=True,
                verify_real_host_manually=not no_tls_verify,
            )
        if ech_config_list:
            return TlsStealthPlan(
                use_tls=True,
                real_host=clean_host,
                configured_sni_mode=mode,
                effective_sni_mode="ech",
                wire_sni=ech_outer,
                fragment_client_hello=False,
                verify_real_host_manually=False,
                use_ech=True,
                ech_config_list=ech_config_list,
                allow_ech_fallback=not explicit_ech,
            )
        return TlsStealthPlan(
            use_tls=True,
            real_host=clean_host,
            configured_sni_mode=mode,
            effective_sni_mode="fragment",
            wire_sni=clean_host,
            fragment_client_hello=True,
            verify_real_host_manually=False,
        )

    if mode == "fragment":
        if clean_sni is not None:
            return TlsStealthPlan(
                use_tls=True,
                real_host=clean_host,
                configured_sni_mode=mode,
                effective_sni_mode="fragment",
                wire_sni=clean_sni,
                fragment_client_hello=True,
                verify_real_host_manually=not no_tls_verify,
            )
        return TlsStealthPlan(
            use_tls=True,
            real_host=clean_host,
            configured_sni_mode=mode,
            effective_sni_mode="fragment",
            wire_sni=clean_host,
            fragment_client_hello=True,
            verify_real_host_manually=False,
        )

    if mode == "none":
        return TlsStealthPlan(
            use_tls=True,
            real_host=clean_host,
            configured_sni_mode=mode,
            effective_sni_mode="none",
            wire_sni=None,
            fragment_client_hello=False,
            verify_real_host_manually=not no_tls_verify,
        )

    # mode == "plain"
    if clean_sni is not None:
        return TlsStealthPlan(
            use_tls=True,
            real_host=clean_host,
            configured_sni_mode=mode,
            effective_sni_mode="plain",
            wire_sni=clean_sni,
            fragment_client_hello=False,
            verify_real_host_manually=not no_tls_verify,
        )
    return TlsStealthPlan(
        use_tls=True,
        real_host=clean_host,
        configured_sni_mode=mode,
        effective_sni_mode="plain",
        wire_sni=clean_host,
        fragment_client_hello=False,
        verify_real_host_manually=False,
    )


def build_stealth_ssl_context(
    plan: TlsStealthPlan,
    *,
    no_tls_verify: bool = False,
    base_ssl_context: Optional[ssl.SSLContext] = None,
) -> ssl.SSLContext:
    """Build an ``ssl.SSLContext`` configured for *plan*."""
    if base_ssl_context is not None:
        ctx = base_ssl_context
    else:
        ctx = ssl.create_default_context()

    if no_tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif plan.verify_real_host_manually:
        # Verify the certificate chain against trusted CAs, then enforce RFC 6125
        # hostname verification against `plan.real_host` before sending any app bytes.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

    return ctx


def _dnsname_match(pattern: str, hostname: str) -> bool:
    """Strict RFC 6125 §6.4.3 DNS hostname/wildcard matching."""
    # Certificate SAN/CN patterns must never be whitespace-padded, trailing-dot, or control chars.
    if not pattern or pattern.startswith(".") or pattern.endswith("."):
        return False
    if any(ord(ch) < 0x21 or ord(ch) > 0x7E for ch in pattern):
        return False

    pat = pattern.lower()
    host = hostname.strip().rstrip(".").lower()
    if not host or "\x00" in host:
        return False

    if "*" not in pat:
        return pat == host

    pat_labels = pat.split(".")
    host_labels = host.split(".")

    # Wildcard must match exactly one label, and pattern must have at least 3 labels
    # (rejects `*` and `*.tld`) with no empty labels.
    if len(pat_labels) != len(host_labels) or len(pat_labels) < 3:
        return False
    if any(not lbl for lbl in pat_labels) or any(not lbl for lbl in host_labels):
        return False

    # Wildcard may appear ONLY in the leftmost label.
    pat_left = pat_labels[0]
    host_left = host_labels[0]
    if any("*" in lbl for lbl in pat_labels[1:]):
        return False
    if pat_labels[1:] != host_labels[1:]:
        return False

    # RFC 6125 §6.4.3: do not match wildcards in IDNA A-labels (`xn--...`).
    if pat_left.startswith("xn--") or host_left.startswith("xn--"):
        return False

    if pat_left.count("*") != 1:
        return False

    if pat_left == "*":
        return len(host_left) > 0

    prefix, suffix = pat_left.split("*", 1)
    # Partial-label wildcard `*` must match at least 1 character.
    if len(host_left) <= len(prefix) + len(suffix):
        return False
    return host_left.startswith(prefix) and host_left.endswith(suffix)


def verify_cert_hostname(cert: Optional[Dict[str, Any]], hostname: str) -> None:
    """Verify ``cert`` (from ``getpeercert()``) against ``hostname`` per RFC 6125.

    Compatible with Python 3.9 through 3.14+ (does not depend on removed ``ssl.match_hostname``).
    Raises ``ssl.SSLCertVerificationError`` on mismatch or missing certificate.
    """
    if not cert:
        raise ssl.SSLCertVerificationError("empty or missing peer certificate")

    cleaned = normalize_hostname(hostname)
    if not cleaned:
        raise ssl.SSLCertVerificationError("cannot verify certificate against empty hostname")

    san_entries = cert.get("subjectAltName") or ()

    # Case 1: IP address literal -> must match an IP Address SAN (no CN fallback).
    if is_ip_literal(cleaned):
        ip_str = cleaned.split("%", 1)[0]
        target_ip = ipaddress.ip_address(ip_str)
        ip_sans: List[str] = []
        for key, value in san_entries:
            if key == "IP Address":
                ip_sans.append(str(value))
                try:
                    if ipaddress.ip_address(str(value).strip()) == target_ip:
                        return
                except ValueError:
                    continue
        if ip_sans:
            raise ssl.SSLCertVerificationError(
                f"IP address {cleaned!r} doesn't match certificate IP SANs: {', '.join(ip_sans)}"
            )
        raise ssl.SSLCertVerificationError(
            f"IP address {cleaned!r} doesn't match certificate (no IP Address SANs)"
        )

    # Case 2: DNS hostname -> ASCII IDNA form.
    try:
        ascii_host = cleaned.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ssl.SSLCertVerificationError(f"invalid hostname {hostname!r}: {exc}") from exc

    # RFC 6125 / CA/B Forum: when subjectAltName is present at all, never fall back to CN.
    if san_entries:
        dns_sans = [str(value) for key, value in san_entries if key == "DNS"]
        for pattern in dns_sans:
            if _dnsname_match(pattern, ascii_host):
                return
        if dns_sans:
            raise ssl.SSLCertVerificationError(
                f"hostname {ascii_host!r} doesn't match certificate DNS SANs: {', '.join(dns_sans)}"
            )
        raise ssl.SSLCertVerificationError(
            f"hostname {ascii_host!r} doesn't match certificate (subjectAltName present with no DNS entries)"
        )

    # Fall back to subject CN ONLY when no subjectAltName extension is present.
    common_names: List[str] = []
    for rdn in cert.get("subject") or ():
        for attr_name, attr_val in rdn:
            if attr_name == "commonName":
                common_names.append(str(attr_val))
                if _dnsname_match(str(attr_val), ascii_host):
                    return

    if common_names:
        raise ssl.SSLCertVerificationError(
            f"hostname {ascii_host!r} doesn't match certificate CN: {', '.join(common_names)}"
        )
    raise ssl.SSLCertVerificationError(
        f"hostname {ascii_host!r} doesn't match certificate (no DNS SANs or CN)"
    )


def split_client_hello(data: bytes, *, sni_hint: Optional[str] = None) -> List[bytes]:
    """Split an initial TLS ClientHello record into small TCP fragments.

    If ``sni_hint`` appears inside the ClientHello, split boundaries cut both after
    the 5-byte TLS record header AND directly through the SNI hostname bytes so
    stateless single-packet DPI never observes the full SNI in one TCP segment.
    """
    n = len(data)
    # TLS Handshake record (0x16) with legacy version 0x03 0x0x
    if n < 6 or data[0] != 0x16 or data[1] != 0x03:
        return [data]

    cuts = {5}

    if sni_hint:
        try:
            sni_bytes = normalize_hostname(sni_hint).encode("idna")
        except UnicodeError:
            sni_bytes = sni_hint.encode("ascii", errors="ignore")
        if len(sni_bytes) >= 2:
            pos = data.lower().find(sni_bytes.lower(), 5)
            if pos != -1:
                if len(sni_bytes) >= 4:
                    cuts.add(pos + len(sni_bytes) // 3)
                    cuts.add(pos + (2 * len(sni_bytes)) // 3)
                else:
                    cuts.add(pos + len(sni_bytes) // 2)

    if len(cuts) == 1 and n > 40:
        cuts.add(40)

    sorted_cuts = sorted(c for c in cuts if 0 < c < n)
    if not sorted_cuts:
        return [data]

    chunks: List[bytes] = []
    prev = 0
    for cut in sorted_cuts:
        chunks.append(data[prev:cut])
        prev = cut
    chunks.append(data[prev:])
    return chunks


class ClientHelloFragmentingTransport:
    """``asyncio.Transport`` wrapper that splits the initial TLS ClientHello across TCP segments.

    After the initial ClientHello fragments are flushed, switches to zero-overhead
    passthrough directly to the underlying TCP transport. Uses only loop timers
    (no background tasks or extra sockets) and cancels pending timers on close/abort.
    """

    _start_tls_compatible = True

    def __init__(
        self,
        transport: asyncio.Transport,
        loop: asyncio.AbstractEventLoop,
        *,
        sni_hint: Optional[str] = None,
        fragment_delay: float = _DEFAULT_FRAGMENT_DELAY,
    ) -> None:
        self._transport = transport
        self._loop = loop
        self._sni_hint = sni_hint
        self._fragment_delay = max(0.0, fragment_delay)
        self._first_write_seen = False
        self._passthrough = False
        self._closed = False
        self._pending: Deque[bytes] = collections.deque()
        self._pending_bytes = 0
        self._timer: Optional[asyncio.TimerHandle] = None
        self.fragmented = False
        self.fragment_count = 0

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _flush_next(self) -> None:
        self._timer = None
        if self._closed or self._transport.is_closing():
            self._pending.clear()
            self._pending_bytes = 0
            return
        if not self._pending:
            self._passthrough = True
            return
        chunk = self._pending.popleft()
        self._pending_bytes -= len(chunk)
        self._transport.write(chunk)
        if self._pending:
            self._timer = self._loop.call_later(self._fragment_delay, self._flush_next)
        else:
            self._passthrough = True

    def write(self, data: Union[bytes, bytearray, memoryview]) -> None:
        if self._closed:
            return
        if self._passthrough:
            self._transport.write(data)
            return

        raw = bytes(data)
        if not raw:
            return

        if not self._first_write_seen:
            self._first_write_seen = True
            chunks = split_client_hello(raw, sni_hint=self._sni_hint)
            if len(chunks) > 1:
                self.fragmented = True
                self.fragment_count = len(chunks)
                self._transport.write(chunks[0])
                for piece in chunks[1:]:
                    self._pending.append(piece)
                    self._pending_bytes += len(piece)
                self._timer = self._loop.call_later(self._fragment_delay, self._flush_next)
                return
            self._passthrough = True
            self._transport.write(raw)
            return

        # Additional write arrived before ClientHello fragments finished draining:
        # preserve strict FIFO ordering.
        self._pending.append(raw)
        self._pending_bytes += len(raw)

    def writelines(self, list_of_data: Sequence[Union[bytes, bytearray, memoryview]]) -> None:
        if self._passthrough:
            self._transport.writelines(list_of_data)
            return
        for item in list_of_data:
            self.write(item)

    def get_write_buffer_size(self) -> int:
        return self._transport.get_write_buffer_size() + self._pending_bytes

    def close(self) -> None:
        self._closed = True
        self._cancel_timer()
        self._pending.clear()
        self._pending_bytes = 0
        self._transport.close()

    def abort(self) -> None:
        self._closed = True
        self._cancel_timer()
        self._pending.clear()
        self._pending_bytes = 0
        self._transport.abort()

    def _force_close(self, exc: Optional[BaseException]) -> None:
        self._closed = True
        self._cancel_timer()
        self._pending.clear()
        self._pending_bytes = 0
        force_close = getattr(self._transport, "_force_close", None)
        if callable(force_close):
            force_close(exc)
        else:
            self._transport.abort()

    def is_closing(self) -> bool:
        return self._closed or self._transport.is_closing()

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        self._transport.set_protocol(protocol)

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self._transport.get_protocol()

    def pause_reading(self) -> None:
        self._transport.pause_reading()

    def resume_reading(self) -> None:
        self._transport.resume_reading()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return self._transport.get_extra_info(name, default)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._transport, name)


async def resolve_target_ips(
    hostname: str,
    doh_config: DohConfig,
    *,
    doh_timeout: float = 3.0,
    doh_ssl_context: Optional[ssl.SSLContext] = None,
    on_warn: Optional[Callable[[str], None]] = None,
) -> Tuple[Optional[Tuple[str, ...]], Optional[DohResult], bool]:
    """Resolve target IPs according to *doh_config*.

    Returns ``(ips_or_none_for_system_dns, doh_result, doh_fell_back)``.
    """
    if doh_config.mode == "off" or should_skip_doh(hostname):
        return None, None, False

    try:
        res = await resolve_doh(
            hostname,
            endpoints=doh_config.endpoints,
            timeout=doh_timeout,
            ssl_context=doh_ssl_context,
        )
        return res.ips, res, False
    except DohError as exc:
        if doh_config.mode == "strict":
            raise
        msg = f"DoH resolution failed for {hostname!r} ({exc}); falling back to system DNS"
        logger.warning("%s", msg)
        if on_warn is not None:
            try:
                on_warn(msg)
            except Exception:
                pass
        return None, None, True


async def connect_tcp_socket(
    ips: Sequence[str],
    port: int,
    *,
    timeout: float = 10.0,
) -> Tuple[socket.socket, str]:
    """Connect a non-blocking TCP socket to the first reachable IP in *ips* with ``TCP_NODELAY``."""
    if not ips:
        raise TunnelConnectionError("no target IP addresses available to connect")

    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.5, timeout)
    last_exc: Optional[Exception] = None

    for idx, ip in enumerate(ips):
        remaining = deadline - loop.time()
        if remaining <= 0:
            break
        remaining_ips = len(ips) - idx
        attempt_timeout = remaining if remaining_ips == 1 else min(remaining, max(3.0, remaining / remaining_ips))

        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout=attempt_timeout)
            return sock, ip
        except asyncio.CancelledError:
            sock.close()
            raise
        except Exception as exc:
            sock.close()
            last_exc = exc

    raise TunnelConnectionError(
        f"failed to connect to any resolved IP ({', '.join(ips)}): {last_exc or 'timed out'}"
    ) from last_exc


async def connect_system_tcp_socket(
    host: str,
    port: int,
    *,
    timeout: float = 10.0,
) -> Tuple[socket.socket, str]:
    """Resolve via system DNS and connect a non-blocking TCP socket with ``TCP_NODELAY``."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except asyncio.TimeoutError as exc:
        raise TunnelConnectionError(f"DNS lookup timed out for {host!r}") from exc
    except OSError as exc:
        raise TunnelConnectionError(f"DNS lookup failed for {host!r}: {exc}") from exc

    ips: List[str] = []
    seen = set()
    for _fam, _type, _proto, _canon, sockaddr in infos:
        ip = str(sockaddr[0])
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)

    return await connect_tcp_socket(ips, port, timeout=timeout)


class _HandshakeBufferProtocol(asyncio.Protocol):
    """Temporary protocol used during ``loop.start_tls`` so failed handshakes never invoke
    ``connection_lost`` on an uninitialized upper-layer protocol (like ``ClientConnection``).
    """

    def __init__(self) -> None:
        self.buffered: bytearray = bytearray()
        self.eof_seen = False

    def data_received(self, data: bytes) -> None:
        self.buffered.extend(data)

    def eof_received(self) -> Optional[bool]:
        self.eof_seen = True
        return True


async def upgrade_transport_tls(
    raw_sock: socket.socket,
    protocol: asyncio.BaseProtocol,
    plan: TlsStealthPlan,
    *,
    ssl_context: ssl.SSLContext,
    handshake_timeout: float = 10.0,
    fragment_delay: float = _DEFAULT_FRAGMENT_DELAY,
    call_connection_made: bool = False,
) -> Tuple[asyncio.Transport, bool, int, Optional[str]]:
    """Attach *raw_sock* to the event loop and perform stealth TLS upgrade via ``loop.start_tls``.

    Returns ``(tls_transport, fragmented, fragment_count, tls_version)``.
    Guarantees ``raw_sock`` and intermediate transports are closed on any error or cancellation.
    """
    loop = asyncio.get_running_loop()
    raw_transport: Optional[asyncio.Transport] = None
    try:
        raw_transport, _ = await loop.create_connection(asyncio.Protocol, sock=raw_sock)
    except BaseException:
        try:
            raw_sock.close()
        except OSError:
            pass
        raise

    # raw_sock is now owned by raw_transport.
    frag_wrapper: Optional[ClientHelloFragmentingTransport] = None
    base_transport: Any = raw_transport
    if plan.fragment_client_hello:
        frag_wrapper = ClientHelloFragmentingTransport(
            raw_transport,
            loop,
            sni_hint=plan.wire_sni,
            fragment_delay=fragment_delay,
        )
        base_transport = frag_wrapper

    handshake_proto = _HandshakeBufferProtocol()
    try:
        tls_transport = await loop.start_tls(
            base_transport,
            handshake_proto,
            ssl_context,
            server_hostname=plan.wire_sni,
            ssl_handshake_timeout=handshake_timeout,
        )
    except BaseException:
        base_transport.abort()
        raise

    if tls_transport is None:  # pragma: no cover - defensive
        base_transport.abort()
        raise TunnelConnectionError("loop.start_tls returned None")

    # Enforce strict RFC 6125 certificate verification against the REAL target hostname
    # BEFORE attaching the application protocol or sending any application bytes.
    if plan.verify_real_host_manually:
        try:
            peercert = tls_transport.get_extra_info("peercert")
            verify_cert_hostname(peercert, plan.real_host)
        except BaseException:
            tls_transport.abort()
            raise

    tls_transport.set_protocol(protocol)
    if call_connection_made:
        protocol.connection_made(tls_transport)
        if handshake_proto.buffered and hasattr(protocol, "data_received"):
            protocol.data_received(bytes(handshake_proto.buffered))  # type: ignore[attr-defined]
        if handshake_proto.eof_seen and hasattr(protocol, "eof_received"):
            protocol.eof_received()  # type: ignore[attr-defined]

    ssl_obj = tls_transport.get_extra_info("ssl_object")
    tls_version = ssl_obj.version() if ssl_obj is not None else None
    fragmented = frag_wrapper.fragmented if frag_wrapper is not None else False
    fragment_count = frag_wrapper.fragment_count if frag_wrapper is not None else 0
    return tls_transport, fragmented, fragment_count, tls_version
