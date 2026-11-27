"""Zero-dependency RFC 8484 DNS-over-HTTPS (DoH) client & RFC 1035/9460 DNS wire codec.

Uses IP-based DoH endpoints over stdlib ``ssl`` + ``asyncio`` so default resolution
causes zero bootstrap plaintext DNS leaks.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from .errors import DohError

DNS_TYPE_A = 1
DNS_TYPE_CNAME = 5
DNS_TYPE_AAAA = 28
DNS_TYPE_HTTPS = 65

DNS_CLASS_IN = 1

SVCPARAM_ALPN = 1
SVCPARAM_IPV4HINT = 4
SVCPARAM_ECH = 5
SVCPARAM_IPV6HINT = 6

DEFAULT_DOH_ENDPOINTS: Tuple[str, ...] = (
    "https://1.0.0.1/dns-query",
    "https://223.5.5.5/dns-query",
    "https://1.1.1.1/dns-query",
    "https://8.8.4.4/dns-query",
)

DEFAULT_DOH_TIMEOUT = 3.0

_MAX_HTTP_HEADER_BYTES = 32 * 1024
_MAX_DNS_RESPONSE_BYTES = 65536
_MAX_DNS_POINTER_JUMPS = 128

_DEFAULT_DOH_SSL_CONTEXT: Optional[ssl.SSLContext] = None


def _get_default_doh_ssl_context() -> ssl.SSLContext:
    global _DEFAULT_DOH_SSL_CONTEXT
    if _DEFAULT_DOH_SSL_CONTEXT is None:
        _DEFAULT_DOH_SSL_CONTEXT = ssl.create_default_context()
    return _DEFAULT_DOH_SSL_CONTEXT


@dataclass(frozen=True)
class DohConfig:
    """Resolved DNS-over-HTTPS configuration."""

    mode: str = "auto"  # "auto" | "strict" | "off"
    endpoints: Tuple[str, ...] = DEFAULT_DOH_ENDPOINTS
    custom: bool = False

    def to_config_string(self) -> str:
        if self.mode == "off":
            return "off"
        if self.custom and self.endpoints:
            return ",".join(self.endpoints)
        return self.mode


@dataclass(frozen=True)
class HttpsRecord:
    """Parsed RFC 9460 HTTPS (Type 65) resource record."""

    priority: int
    target_name: str
    alpn: Tuple[str, ...] = ()
    ipv4_hints: Tuple[str, ...] = ()
    ipv6_hints: Tuple[str, ...] = ()
    ech: Optional[bytes] = None
    svc_params: Dict[int, bytes] = field(default_factory=dict)


@dataclass(frozen=True)
class DnsResponse:
    """Parsed DNS wire response."""

    query_id: int
    rcode: int
    ipv4: Tuple[str, ...] = ()
    ipv6: Tuple[str, ...] = ()
    cnames: Tuple[str, ...] = ()
    https_records: Tuple[HttpsRecord, ...] = ()


@dataclass(frozen=True)
class DohResult:
    """Combined A/AAAA/HTTPS resolution result from DoH."""

    hostname: str
    ips: Tuple[str, ...]
    ipv4: Tuple[str, ...]
    ipv6: Tuple[str, ...]
    https_records: Tuple[HttpsRecord, ...] = ()
    ech_configs: Tuple[bytes, ...] = ()
    endpoint: Optional[str] = None
    used_doh: bool = True

    @property
    def ech_config_list(self) -> Optional[bytes]:
        return self.ech_configs[0] if self.ech_configs else None


def normalize_hostname(hostname: str) -> str:
    """Normalize a hostname by stripping whitespace, IPv6 brackets, and trailing dots."""
    cleaned = hostname.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    return cleaned.rstrip(".").lower()


def is_ip_literal(hostname: str) -> bool:
    """Return True if *hostname* is an IPv4 or IPv6 literal."""
    cleaned = normalize_hostname(hostname)
    if not cleaned:
        return False
    # Strip IPv6 zone index if present (e.g. fe80::1%eth0)
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def should_skip_doh(hostname: str) -> bool:
    """Return True if DoH should be skipped (IP literals, localhost, *.localhost, *.local)."""
    cleaned = normalize_hostname(hostname)
    if not cleaned:
        return True
    if is_ip_literal(cleaned):
        return True
    if cleaned == "localhost" or cleaned.endswith(".localhost") or cleaned.endswith(".local"):
        return True
    return False


def _is_loopback_host(host: str) -> bool:
    return normalize_hostname(host) in ("127.0.0.1", "::1", "localhost")


def _validate_doh_url(url: str) -> str:
    cleaned = url.strip()
    parsed = urlsplit(cleaned)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host:
        raise ValueError(f"invalid DoH endpoint URL {url!r}: missing host")
    if scheme == "https":
        return cleaned
    if scheme == "http" and _is_loopback_host(host):
        return cleaned
    if scheme == "http":
        raise ValueError(
            f"invalid DoH endpoint URL {url!r}: cleartext http:// is only permitted for loopback hosts (127.0.0.1, ::1, localhost)"
        )
    raise ValueError(
        f"invalid DoH endpoint URL {url!r}: expected https://... (or loopback http://... for local testing)"
    )


def parse_doh_option(
    value: Optional[Union[bool, str, Sequence[str]]],
    *,
    default_mode: str = "auto",
) -> DohConfig:
    """Parse a DoH configuration value (bool, mode string, comma-separated URLs, or URL list)."""
    if value is None:
        return parse_doh_option(default_mode)

    if isinstance(value, bool):
        if value:
            return DohConfig(mode="auto", endpoints=DEFAULT_DOH_ENDPOINTS, custom=False)
        return DohConfig(mode="off", endpoints=(), custom=False)

    if isinstance(value, str):
        trimmed = value.strip()
        if not trimmed:
            return parse_doh_option(default_mode)
        lower = trimmed.lower()
        if lower in ("auto", "true", "1", "on", "yes"):
            return DohConfig(mode="auto", endpoints=DEFAULT_DOH_ENDPOINTS, custom=False)
        if lower == "strict":
            return DohConfig(mode="strict", endpoints=DEFAULT_DOH_ENDPOINTS, custom=False)
        if lower in ("off", "false", "0", "no", "none", "disabled"):
            return DohConfig(mode="off", endpoints=(), custom=False)

        parts = [p.strip() for p in trimmed.split(",") if p.strip()]
        if not parts:
            raise ValueError(f"invalid DoH option {value!r}")
        validated = tuple(_validate_doh_url(p) for p in parts)
        # Explicitly configured custom DoH URLs do not silently fall back to plaintext system DNS.
        return DohConfig(mode="strict", endpoints=validated, custom=True)

    # Sequence of URLs (reject bytes/bytearray)
    if isinstance(value, (bytes, bytearray)):
        raise ValueError("DoH option must be bool, str, or sequence of URL strings")
    endpoints = tuple(_validate_doh_url(str(item)) for item in value if str(item).strip())
    if not endpoints:
        return DohConfig(mode="off", endpoints=(), custom=False)
    return DohConfig(mode="strict", endpoints=endpoints, custom=True)


def encode_dns_query(hostname: str, qtype: int, *, query_id: int = 0) -> bytes:
    """Encode an RFC 1035 DNS query message for ``hostname`` and ``qtype``."""
    cleaned = normalize_hostname(hostname)
    if not cleaned:
        raise ValueError("hostname must not be empty")
    try:
        ascii_host = cleaned.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"invalid IDNA hostname {hostname!r}: {exc}") from exc

    qname_parts: List[bytes] = []
    total_len = 1  # trailing root 0x00
    for label in ascii_host.split("."):
        raw_label = label.encode("ascii")
        if not raw_label or len(raw_label) > 63:
            raise ValueError(f"invalid DNS label {label!r} in hostname {hostname!r}")
        total_len += 1 + len(raw_label)
        qname_parts.append(bytes([len(raw_label)]) + raw_label)
    if total_len > 255:
        raise ValueError(f"DNS hostname too long: {hostname!r}")
    qname_parts.append(b"\x00")

    header = struct.pack("!HHHHHH", query_id & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = b"".join(qname_parts) + struct.pack("!HH", qtype & 0xFFFF, DNS_CLASS_IN)
    return header + question


def _read_dns_name(packet: bytes, offset: int, *, allow_compression: bool = True) -> Tuple[str, int]:
    """Decode an RFC 1035 domain name starting at *offset*, returning ``(name, next_offset)``."""
    labels: List[str] = []
    pos = offset
    end_offset: Optional[int] = None
    jumps = 0
    visited = set()

    while True:
        if pos >= len(packet):
            raise DohError("truncated DNS domain name")
        length = packet[pos]
        if length == 0:
            if end_offset is None:
                end_offset = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if not allow_compression:
                raise DohError("unexpected DNS name compression pointer in SVCB/HTTPS target")
            if pos + 1 >= len(packet):
                raise DohError("truncated DNS compression pointer")
            ptr = ((length & 0x3F) << 8) | packet[pos + 1]
            if ptr >= len(packet):
                raise DohError("DNS compression pointer out of bounds")
            if ptr in visited:
                raise DohError("DNS compression pointer loop detected")
            visited.add(ptr)
            jumps += 1
            if jumps > _MAX_DNS_POINTER_JUMPS:
                raise DohError("too many DNS compression pointer jumps")
            if end_offset is None:
                end_offset = pos + 2
            pos = ptr
            continue
        if length & 0xC0:
            raise DohError(f"unsupported DNS label type bits: 0x{length:02x}")
        pos += 1
        if pos + length > len(packet):
            raise DohError("truncated DNS label")
        labels.append(packet[pos : pos + length].decode("ascii", errors="replace"))
        pos += length

    return ".".join(labels), end_offset if end_offset is not None else pos


def _parse_https_rdata(rdata: bytes) -> HttpsRecord:
    """Parse RFC 9460 HTTPS/SVCB RDATA including alpn, ipv4hint, ech (key 5), and ipv6hint."""
    if len(rdata) < 3:
        raise DohError("truncated HTTPS RR rdata")
    (priority,) = struct.unpack_from("!H", rdata, 0)
    target_name, pos = _read_dns_name(rdata, 2, allow_compression=False)

    alpn_list: List[str] = []
    ipv4_hints: List[str] = []
    ipv6_hints: List[str] = []
    ech_bytes: Optional[bytes] = None
    svc_params: Dict[int, bytes] = {}

    if priority > 0:
        while pos < len(rdata):
            if pos + 4 > len(rdata):
                raise DohError("truncated HTTPS SvcParam header")
            key, val_len = struct.unpack_from("!HH", rdata, pos)
            pos += 4
            if pos + val_len > len(rdata):
                raise DohError("truncated HTTPS SvcParam value")
            val = rdata[pos : pos + val_len]
            pos += val_len
            svc_params[key] = val

            if key == SVCPARAM_ALPN:
                apos = 0
                while apos < len(val):
                    alen = val[apos]
                    apos += 1
                    if apos + alen > len(val):
                        raise DohError("truncated ALPN SvcParam entry")
                    alpn_list.append(val[apos : apos + alen].decode("ascii", errors="replace"))
                    apos += alen
            elif key == SVCPARAM_IPV4HINT:
                if len(val) % 4 != 0:
                    raise DohError("invalid ipv4hint SvcParam length")
                for off in range(0, len(val), 4):
                    ipv4_hints.append(str(ipaddress.IPv4Address(val[off : off + 4])))
            elif key == SVCPARAM_ECH:
                if val:
                    ech_bytes = val
            elif key == SVCPARAM_IPV6HINT:
                if len(val) % 16 != 0:
                    raise DohError("invalid ipv6hint SvcParam length")
                for off in range(0, len(val), 16):
                    ipv6_hints.append(str(ipaddress.IPv6Address(val[off : off + 16])))

    return HttpsRecord(
        priority=priority,
        target_name=target_name,
        alpn=tuple(alpn_list),
        ipv4_hints=tuple(ipv4_hints),
        ipv6_hints=tuple(ipv6_hints),
        ech=ech_bytes,
        svc_params=svc_params,
    )


def parse_ech_public_name(ech_config_list: bytes) -> Optional[str]:
    """Extract the first ``public_name`` from an RFC 9849 ECHConfigList, if valid."""
    if len(ech_config_list) < 2:
        return None
    (list_len,) = struct.unpack_from("!H", ech_config_list, 0)
    if 2 + list_len > len(ech_config_list):
        return None
    pos = 2
    end = 2 + list_len
    while pos + 4 <= end:
        version, cfg_len = struct.unpack_from("!HH", ech_config_list, pos)
        pos += 4
        if pos + cfg_len > end:
            return None
        cfg = ech_config_list[pos : pos + cfg_len]
        pos += cfg_len
        if version != 0xFE0D:
            continue
        # ECHConfigContents: config_id(1) + kem_id(2) + pk_len(2) + pk + cs_len(2) + cs + max_name_len(1) + pub_name_len(1) + pub_name
        cpos = 3
        if cpos + 2 > len(cfg):
            continue
        (pk_len,) = struct.unpack_from("!H", cfg, cpos)
        cpos += 2 + pk_len
        if cpos + 2 > len(cfg):
            continue
        (cs_len,) = struct.unpack_from("!H", cfg, cpos)
        cpos += 2 + cs_len + 1  # +1 for maximum_name_length
        if cpos + 1 > len(cfg):
            continue
        pub_len = cfg[cpos]
        cpos += 1
        if pub_len > 0 and cpos + pub_len <= len(cfg):
            return cfg[cpos : cpos + pub_len].decode("ascii", errors="replace")
    return None


def decode_dns_response(packet: bytes) -> DnsResponse:
    """Decode an RFC 1035 DNS wire response message."""
    if len(packet) < 12:
        raise DohError(f"DNS response too short ({len(packet)} bytes)")

    qid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack_from("!HHHHHH", packet, 0)
    if (flags & 0x8000) == 0:
        raise DohError("DNS message does not have QR response bit set")

    rcode = flags & 0x000F
    if rcode not in (0, 3):  # NOERROR, NXDOMAIN
        raise DohError(f"DNS server returned error RCODE {rcode}")

    pos = 12
    for _ in range(qdcount):
        _, pos = _read_dns_name(packet, pos)
        if pos + 4 > len(packet):
            raise DohError("truncated DNS question section")
        pos += 4

    ipv4: List[str] = []
    ipv6: List[str] = []
    cnames: List[str] = []
    https_records: List[HttpsRecord] = []

    for _ in range(ancount):
        _, pos = _read_dns_name(packet, pos)
        if pos + 10 > len(packet):
            raise DohError("truncated DNS answer header")
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", packet, pos)
        pos += 10
        if pos + rdlength > len(packet):
            raise DohError("truncated DNS answer RDATA")
        rdata = packet[pos : pos + rdlength]
        pos += rdlength

        if rclass != DNS_CLASS_IN:
            continue
        if rtype == DNS_TYPE_A and rdlength == 4:
            ipv4.append(str(ipaddress.IPv4Address(rdata)))
        elif rtype == DNS_TYPE_AAAA and rdlength == 16:
            ipv6.append(str(ipaddress.IPv6Address(rdata)))
        elif rtype == DNS_TYPE_CNAME:
            cname, _ = _read_dns_name(packet, pos - rdlength)
            cnames.append(cname)
        elif rtype == DNS_TYPE_HTTPS:
            https_records.append(_parse_https_rdata(rdata))

    return DnsResponse(
        query_id=qid,
        rcode=rcode,
        ipv4=tuple(ipv4),
        ipv6=tuple(ipv6),
        cnames=tuple(cnames),
        https_records=tuple(https_records),
    )


async def _read_chunked_body(reader: asyncio.StreamReader, max_bytes: int) -> bytes:
    out = bytearray()
    while True:
        line = await reader.readline()
        if not line or not line.endswith(b"\n"):
            raise DohError("truncated chunked DoH HTTP response")
        size_token = line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_token, 16)
        except ValueError as exc:
            raise DohError(f"invalid chunked size in DoH HTTP response: {size_token!r}") from exc
        if chunk_size < 0:
            raise DohError("negative chunk size in DoH HTTP response")
        if chunk_size == 0:
            # Drain trailers until empty line
            while True:
                trailer = await reader.readline()
                if not trailer or trailer in (b"\r\n", b"\n"):
                    break
            break
        if len(out) + chunk_size > max_bytes:
            raise DohError("DoH HTTP response body exceeds maximum allowed size")
        chunk = await reader.readexactly(chunk_size)
        out.extend(chunk)
        crlf = await reader.readexactly(2)
        if crlf != b"\r\n":
            raise DohError("malformed chunk terminator in DoH HTTP response")
    return bytes(out)


async def _read_http_response(reader: asyncio.StreamReader) -> Tuple[int, Dict[str, str], bytes]:
    raw_head = bytearray()
    while b"\r\n\r\n" not in raw_head:
        line = await reader.readline()
        if not line:
            raise DohError("unexpected EOF reading DoH HTTP response headers")
        raw_head.extend(line)
        if len(raw_head) > _MAX_HTTP_HEADER_BYTES:
            raise DohError("DoH HTTP response headers too large")

    head_text = bytes(raw_head).decode("iso-8859-1")
    lines = head_text.split("\r\n")
    status_parts = lines[0].split(" ", 2)
    if len(status_parts) < 2 or not status_parts[0].startswith("HTTP/"):
        raise DohError(f"invalid DoH HTTP status line: {lines[0]!r}")
    try:
        status_code = int(status_parts[1])
    except ValueError as exc:
        raise DohError(f"invalid DoH HTTP status code: {status_parts[1]!r}") from exc

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        body = await _read_chunked_body(reader, _MAX_DNS_RESPONSE_BYTES)
    elif "content-length" in headers:
        try:
            cl = int(headers["content-length"])
        except ValueError as exc:
            raise DohError("invalid Content-Length in DoH HTTP response") from exc
        if cl < 0 or cl > _MAX_DNS_RESPONSE_BYTES:
            raise DohError(f"invalid DoH response Content-Length: {cl}")
        body = await reader.readexactly(cl)
    else:
        body = await reader.read(_MAX_DNS_RESPONSE_BYTES + 1)
        if len(body) > _MAX_DNS_RESPONSE_BYTES:
            raise DohError("DoH HTTP response body too large")

    return status_code, headers, body


async def _post_doh_wire(
    endpoint: str,
    query_bytes: bytes,
    *,
    timeout: float = DEFAULT_DOH_TIMEOUT,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> bytes:
    """POST an RFC 8484 ``application/dns-message`` payload to ``endpoint``."""
    parsed = urlsplit(endpoint)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if not host or (scheme != "https" and not (scheme == "http" and _is_loopback_host(host))):
        raise DohError(f"invalid DoH endpoint URL: {endpoint!r}")

    default_port = 443 if scheme == "https" else 80
    port = parsed.port if parsed.port is not None else default_port
    path = parsed.path or "/dns-query"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    host_disp = f"[{host}]" if ":" in host else host
    host_header = f"{host_disp}:{port}" if parsed.port is not None and port != default_port else host_disp

    async def _exchange() -> bytes:
        loop = asyncio.get_running_loop()
        writer: Optional[asyncio.StreamWriter] = None
        raw_sock: Optional[socket.socket] = None

        try:
            if is_ip_literal(host):
                # Direct IP socket connect: zero bootstrap system DNS lookup!
                family = socket.AF_INET6 if ":" in host else socket.AF_INET
                raw_sock = socket.socket(family, socket.SOCK_STREAM)
                raw_sock.setblocking(False)
                try:
                    raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                await loop.sock_connect(raw_sock, (host, port))

                if scheme == "https":
                    ctx = ssl_context if ssl_context is not None else _get_default_doh_ssl_context()
                    reader, writer = await asyncio.open_connection(
                        sock=raw_sock,
                        ssl=ctx,
                        server_hostname=host,
                    )
                else:
                    reader, writer = await asyncio.open_connection(sock=raw_sock)
                # Ownership transferred to StreamWriter's transport.
                raw_sock = None
            else:
                if scheme == "https":
                    ctx = ssl_context if ssl_context is not None else _get_default_doh_ssl_context()
                    reader, writer = await asyncio.open_connection(
                        host,
                        port,
                        ssl=ctx,
                        server_hostname=host,
                    )
                else:
                    reader, writer = await asyncio.open_connection(host, port)

            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"Content-Type: application/dns-message\r\n"
                f"Accept: application/dns-message\r\n"
                f"Content-Length: {len(query_bytes)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode("ascii") + query_bytes
            writer.write(req)
            await writer.drain()

            status_code, _headers, body = await _read_http_response(reader)
            if status_code != 200:
                raise DohError(f"DoH endpoint {endpoint} returned HTTP {status_code}")
            return body
        except BaseException:
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass
            if writer is not None:
                try:
                    writer.transport.abort()
                except Exception:
                    pass
            raise
        finally:
            if writer is not None and not writer.is_closing():
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
                except Exception:
                    try:
                        writer.transport.abort()
                    except Exception:
                        pass

    try:
        return await asyncio.wait_for(_exchange(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise DohError(f"DoH endpoint {endpoint} timed out after {timeout:.1f}s") from exc
    except DohError:
        raise
    except (OSError, ssl.SSLError, asyncio.IncompleteReadError) as exc:
        raise DohError(f"DoH request to {endpoint} failed: {exc}") from exc


async def query_doh_record(
    endpoint: str,
    hostname: str,
    qtype: int,
    *,
    timeout: float = DEFAULT_DOH_TIMEOUT,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> DnsResponse:
    """Query a single DNS record type from a single RFC 8484 DoH endpoint."""
    wire_req = encode_dns_query(hostname, qtype)
    wire_resp = await _post_doh_wire(
        endpoint,
        wire_req,
        timeout=timeout,
        ssl_context=ssl_context,
    )
    return decode_dns_response(wire_resp)


def _dedup_preserve(items: Sequence[str]) -> Tuple[str, ...]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


async def _resolve_single_endpoint(
    endpoint: str,
    hostname: str,
    *,
    timeout: float = DEFAULT_DOH_TIMEOUT,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> DohResult:
    """Resolve A, AAAA, and HTTPS (Type 65) records in parallel against one DoH endpoint."""
    tasks = [
        asyncio.create_task(
            query_doh_record(endpoint, hostname, DNS_TYPE_A, timeout=timeout, ssl_context=ssl_context),
            name=f"neruton-doh-a-{hostname}",
        ),
        asyncio.create_task(
            query_doh_record(endpoint, hostname, DNS_TYPE_AAAA, timeout=timeout, ssl_context=ssl_context),
            name=f"neruton-doh-aaaa-{hostname}",
        ),
        asyncio.create_task(
            query_doh_record(endpoint, hostname, DNS_TYPE_HTTPS, timeout=timeout, ssl_context=ssl_context),
            name=f"neruton-doh-https-{hostname}",
        ),
    ]
    try:
        results: List[Any] = list(await asyncio.gather(*tasks, return_exceptions=True))
    except BaseException:
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise

    a_res, aaaa_res, https_res = results[0], results[1], results[2]

    ipv4: List[str] = []
    ipv6: List[str] = []
    https_records: List[HttpsRecord] = []
    ech_configs: List[bytes] = []
    hint_v4: List[str] = []
    hint_v6: List[str] = []
    errors: List[str] = []
    any_address_query_ok = False

    if isinstance(a_res, DnsResponse):
        any_address_query_ok = True
        ipv4.extend(a_res.ipv4)
    elif isinstance(a_res, BaseException):
        errors.append(f"A: {a_res}")

    if isinstance(aaaa_res, DnsResponse):
        any_address_query_ok = True
        ipv6.extend(aaaa_res.ipv6)
    elif isinstance(aaaa_res, BaseException):
        errors.append(f"AAAA: {aaaa_res}")

    if isinstance(https_res, DnsResponse):
        https_records.extend(https_res.https_records)
        # Prefer lower priority ServiceMode records first.
        sorted_https = sorted(https_res.https_records, key=lambda r: r.priority)
        for rec in sorted_https:
            if rec.ech is not None:
                ech_configs.append(rec.ech)
            hint_v4.extend(rec.ipv4_hints)
            hint_v6.extend(rec.ipv6_hints)

    all_v4 = _dedup_preserve(ipv4 + hint_v4)
    all_v6 = _dedup_preserve(ipv6 + hint_v6)
    all_ips = _dedup_preserve(list(all_v4) + list(all_v6))

    if not any_address_query_ok and not all_ips:
        raise DohError(f"{endpoint} failed ({'; '.join(errors) or 'no answer'})")

    if not all_ips:
        raise DohError(f"{endpoint} returned no A/AAAA records for {hostname!r}")

    return DohResult(
        hostname=normalize_hostname(hostname),
        ips=all_ips,
        ipv4=all_v4,
        ipv6=all_v6,
        https_records=tuple(https_records),
        ech_configs=tuple(ech_configs),
        endpoint=endpoint,
        used_doh=True,
    )


async def resolve_doh(
    hostname: str,
    *,
    endpoints: Sequence[str] = DEFAULT_DOH_ENDPOINTS,
    timeout: float = DEFAULT_DOH_TIMEOUT,
    ssl_context: Optional[ssl.SSLContext] = None,
) -> DohResult:
    """Resolve ``hostname`` via DoH, racing the first two endpoints and falling back across the rest."""
    cleaned = normalize_hostname(hostname)
    if not cleaned:
        raise DohError("cannot resolve empty hostname")

    ep_list = tuple(endpoints)
    if not ep_list:
        raise DohError("no DoH endpoints configured")

    errors: List[str] = []

    # Race the first two endpoints concurrently for low latency both in China and globally.
    if len(ep_list) >= 2:
        race_eps = ep_list[:2]
        remaining_eps = ep_list[2:]
        tasks: Dict[asyncio.Task[DohResult], str] = {
            asyncio.create_task(
                _resolve_single_endpoint(ep, cleaned, timeout=timeout, ssl_context=ssl_context),
                name=f"neruton-doh-race-{idx}",
            ): ep
            for idx, ep in enumerate(race_eps)
        }
        pending = set(tasks.keys())
        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                for finished in done:
                    ep_name = tasks[finished]
                    if finished.cancelled():
                        continue
                    exc = finished.exception()
                    if exc is None:
                        result = finished.result()
                        # Cancel slower racing peer cleanly!
                        for loser in pending:
                            loser.cancel()
                        if pending:
                            await asyncio.gather(*pending, return_exceptions=True)
                        return result
                    errors.append(f"{ep_name}: {exc}")
        except BaseException:
            for t in tasks:
                if not t.done():
                    t.cancel()
            await asyncio.gather(*tasks.keys(), return_exceptions=True)
            raise
    else:
        remaining_eps = ep_list

    # Sequential fallback across remaining endpoints.
    for ep in remaining_eps:
        try:
            return await _resolve_single_endpoint(
                ep,
                cleaned,
                timeout=timeout,
                ssl_context=ssl_context,
            )
        except DohError as exc:
            errors.append(f"{ep}: {exc}")

    raise DohError(f"all DoH endpoints failed for {cleaned!r}: {'; '.join(errors)}")
