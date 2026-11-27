"""Comprehensive unit & local-TLS integration tests for DoH and Hidden SNI stealth transport."""

from __future__ import annotations

import asyncio
import contextlib
import io
import ipaddress
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

from websockets.asyncio.server import ServerConnection, serve
from websockets.datastructures import Headers
from websockets.http11 import Response as WsHttpResponse

import neruton
from neruton.cli import build_parser, main as cli_main
from neruton.client import Tunnel, _open_websocket
from neruton.config import (
    Config,
    load_config,
    resolve_stealth_options,
    save_config,
)
from neruton.doh import (
    DEFAULT_DOH_ENDPOINTS,
    DNS_CLASS_IN,
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    DNS_TYPE_HTTPS,
    SVCPARAM_ALPN,
    SVCPARAM_ECH,
    SVCPARAM_IPV4HINT,
    SVCPARAM_IPV6HINT,
    DohConfig,
    decode_dns_response,
    encode_dns_query,
    parse_doh_option,
    parse_ech_public_name,
    resolve_doh,
    should_skip_doh,
)
from neruton.errors import DohError, NerutonError, TunnelConnectionError, TunnelError
from neruton.tls_stealth import (
    ClientHelloFragmentingTransport,
    build_stealth_ssl_context,
    resolve_target_ips,
    resolve_tls_plan,
    split_client_hello,
    upgrade_transport_tls,
    verify_cert_hostname,
)


def _encode_dns_name(name: str) -> bytes:
    if not name or name == ".":
        return b"\x00"
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _build_ech_config_list(public_name: str = "cloudflare-ech.com") -> bytes:
    pk = b"\x11" * 32
    cipher_suites = struct.pack("!HH", 0x0001, 0x0001)
    pub_bytes = public_name.encode("ascii")
    contents = (
        struct.pack("!BH", 42, 0x0020)  # config_id=42, DHKEM(X25519, HKDF-SHA256)
        + struct.pack("!H", len(pk))
        + pk
        + struct.pack("!H", len(cipher_suites))
        + cipher_suites
        + struct.pack("!BB", 64, len(pub_bytes))
        + pub_bytes
    )
    cfg = struct.pack("!HH", 0xFE0D, len(contents)) + contents
    return struct.pack("!H", len(cfg)) + cfg


def _build_dns_response(
    query: bytes,
    answers: List[Tuple[int, bytes]],
    *,
    rcode: int = 0,
    use_compression: bool = True,
) -> bytes:
    qid = struct.unpack_from("!H", query, 0)[0]
    question = query[12:]
    flags = 0x8180 | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", qid, flags, 1, len(answers), 0, 0)
    ans_bytes = bytearray()
    for rtype, rdata in answers:
        if use_compression:
            ans_bytes.extend(b"\xc0\x0c")  # pointer to QNAME at offset 12
        else:
            ans_bytes.extend(_encode_dns_name("neruton.moer.eu.org"))
        ans_bytes.extend(struct.pack("!HHIH", rtype, DNS_CLASS_IN, 300, len(rdata)))
        ans_bytes.extend(rdata)
    return header + question + bytes(ans_bytes)


def _build_https_rdata(
    *,
    priority: int = 1,
    target: str = ".",
    alpn: Tuple[str, ...] = ("h2",),
    ipv4_hints: Tuple[str, ...] = (),
    ech: Optional[bytes] = None,
    ipv6_hints: Tuple[str, ...] = (),
) -> bytes:
    out = bytearray(struct.pack("!H", priority))
    out.extend(_encode_dns_name(target))
    if priority > 0:
        if alpn:
            val = bytearray()
            for proto in alpn:
                pb = proto.encode("ascii")
                val.append(len(pb))
                val.extend(pb)
            out.extend(struct.pack("!HH", SVCPARAM_ALPN, len(val)) + val)
        if ipv4_hints:
            val = b"".join(ipaddress.IPv4Address(ip).packed for ip in ipv4_hints)
            out.extend(struct.pack("!HH", SVCPARAM_IPV4HINT, len(val)) + val)
        if ech is not None:
            out.extend(struct.pack("!HH", SVCPARAM_ECH, len(ech)) + ech)
        if ipv6_hints:
            val = b"".join(ipaddress.IPv6Address(ip).packed for ip in ipv6_hints)
            out.extend(struct.pack("!HH", SVCPARAM_IPV6HINT, len(val)) + val)
    return bytes(out)


def _generate_self_signed_cert(
    tmp_dir: Path,
    *,
    cn: str,
    san_dns: Tuple[str, ...] = (),
    san_ips: Tuple[str, ...] = (),
) -> Tuple[Path, Path]:
    cert_path = tmp_dir / f"{cn.replace('*', 'wild')}.crt"
    key_path = tmp_dir / f"{cn.replace('*', 'wild')}.key"
    cfg_path = tmp_dir / f"{cn.replace('*', 'wild')}.cnf"

    alt_entries: List[str] = []
    for idx, d in enumerate(san_dns, start=1):
        alt_entries.append(f"DNS.{idx} = {d}")
    for idx, ip in enumerate(san_ips, start=1):
        alt_entries.append(f"IP.{idx} = {ip}")

    ext_section = ""
    if alt_entries:
        ext_section = (
            "[v3_req]\n"
            "subjectAltName = @alt_names\n"
            "[alt_names]\n"
            + "\n".join(alt_entries)
            + "\n"
        )
    else:
        ext_section = "[v3_req]\nbasicConstraints = CA:FALSE\n"

    cfg_path.write_text(
        "[req]\n"
        "distinguished_name = req_distinguished_name\n"
        "x509_extensions = v3_req\n"
        "prompt = no\n"
        "[req_distinguished_name]\n"
        f"CN = {cn}\n"
        + ext_section,
        encoding="utf-8",
    )

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-config",
            str(cfg_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return cert_path, key_path


class _MockDohServer:
    """In-process RFC 8484 DoH HTTP/HTTPS mock server."""

    def __init__(
        self,
        *,
        ipv4: Tuple[str, ...] = ("127.0.0.1",),
        ipv6: Tuple[str, ...] = (),
        ech_bytes: Optional[bytes] = None,
        ipv4_hints: Tuple[str, ...] = (),
        ipv6_hints: Tuple[str, ...] = (),
        delay: float = 0.0,
        status_code: int = 200,
        chunked: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.ech_bytes = ech_bytes
        self.ipv4_hints = ipv4_hints
        self.ipv6_hints = ipv6_hints
        self.delay = delay
        self.status_code = status_code
        self.chunked = chunked
        self.ssl_context = ssl_context
        self.requests: List[Tuple[str, int]] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self.port = 0

    @property
    def url(self) -> str:
        scheme = "https" if self.ssl_context is not None else "http"
        return f"{scheme}://127.0.0.1:{self.port}/dns-query"

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle,
            "127.0.0.1",
            0,
            ssl=self.ssl_context,
        )
        self.port = int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            lines = head.decode("iso-8859-1").split("\r\n")
            headers: Dict[str, str] = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            cl = int(headers.get("content-length", "0"))
            body = await reader.readexactly(cl)

            if self.delay > 0:
                await asyncio.sleep(self.delay)

            # Parse qname + qtype from wire query
            pos = 12
            labels: List[str] = []
            while pos < len(body) and body[pos] != 0:
                n = body[pos]
                labels.append(body[pos + 1 : pos + 1 + n].decode("ascii"))
                pos += 1 + n
            qtype = struct.unpack_from("!H", body, pos + 1)[0]
            self.requests.append((".".join(labels), qtype))

            if self.status_code != 200:
                writer.write(
                    f"HTTP/1.1 {self.status_code} Error\r\nContent-Length: 4\r\nConnection: close\r\n\r\nfail".encode()
                )
                await writer.drain()
                return

            answers: List[Tuple[int, bytes]] = []
            if qtype == DNS_TYPE_A:
                for ip in self.ipv4:
                    answers.append((DNS_TYPE_A, ipaddress.IPv4Address(ip).packed))
            elif qtype == DNS_TYPE_AAAA:
                for ip in self.ipv6:
                    answers.append((DNS_TYPE_AAAA, ipaddress.IPv6Address(ip).packed))
            elif qtype == DNS_TYPE_HTTPS and (self.ech_bytes or self.ipv4_hints or self.ipv6_hints):
                rdata = _build_https_rdata(
                    alpn=("h2", "http/1.1"),
                    ipv4_hints=self.ipv4_hints,
                    ech=self.ech_bytes,
                    ipv6_hints=self.ipv6_hints,
                )
                answers.append((DNS_TYPE_HTTPS, rdata))

            resp_wire = _build_dns_response(body, answers)
            if self.chunked:
                half = max(1, len(resp_wire) // 2)
                p1, p2 = resp_wire[:half], resp_wire[half:]
                payload = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/dns-message\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"Connection: close\r\n\r\n"
                    + f"{len(p1):x}\r\n".encode()
                    + p1
                    + b"\r\n"
                    + f"{len(p2):x}\r\n".encode()
                    + p2
                    + b"\r\n0\r\n\r\n"
                )
            else:
                payload = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/dns-message\r\n"
                    + f"Content-Length: {len(resp_wire)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + resp_wire
                )
            writer.write(payload)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class TestDnsWireCodecAndOptions(unittest.TestCase):
    def test_encode_decode_a_aaaa_cname_and_https_ech(self) -> None:
        q_https = encode_dns_query("neruton.moer.eu.org", DNS_TYPE_HTTPS, query_id=0x1234)
        self.assertEqual(struct.unpack_from("!H", q_https, 0)[0], 0x1234)
        self.assertIn(b"\x07neruton\x04moer\x02eu\x03org\x00", q_https)

        ech_raw = _build_ech_config_list("cloudflare-ech.com")
        https_rdata = _build_https_rdata(
            priority=1,
            target=".",
            alpn=("h2", "h3"),
            ipv4_hints=("104.21.2.247", "172.67.129.230"),
            ech=ech_raw,
            ipv6_hints=("2606:4700:3032::6815:2f7",),
        )
        pkt = _build_dns_response(
            q_https,
            [
                (DNS_TYPE_CNAME, _encode_dns_name("alias.moer.eu.org")),
                (DNS_TYPE_A, ipaddress.IPv4Address("104.21.2.247").packed),
                (DNS_TYPE_AAAA, ipaddress.IPv6Address("2606:4700:3032::6815:2f7").packed),
                (DNS_TYPE_HTTPS, https_rdata),
            ],
        )
        parsed = decode_dns_response(pkt)
        self.assertEqual(parsed.query_id, 0x1234)
        self.assertEqual(parsed.rcode, 0)
        self.assertEqual(parsed.cnames, ("alias.moer.eu.org",))
        self.assertEqual(parsed.ipv4, ("104.21.2.247",))
        self.assertEqual(parsed.ipv6, ("2606:4700:3032::6815:2f7",))
        self.assertEqual(len(parsed.https_records), 1)
        rec = parsed.https_records[0]
        self.assertEqual(rec.priority, 1)
        self.assertEqual(rec.alpn, ("h2", "h3"))
        self.assertEqual(rec.ipv4_hints, ("104.21.2.247", "172.67.129.230"))
        self.assertEqual(rec.ipv6_hints, ("2606:4700:3032::6815:2f7",))
        self.assertEqual(rec.ech, ech_raw)
        self.assertEqual(parse_ech_public_name(rec.ech or b""), "cloudflare-ech.com")

    def test_decode_rejects_pointer_loop_and_servfail(self) -> None:
        # Self-referencing compression pointer at offset 12 -> 0xC0 0x0C
        loop_pkt = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        with self.assertRaises(DohError):
            decode_dns_response(loop_pkt)

        q = encode_dns_query("example.com", DNS_TYPE_A)
        servfail = _build_dns_response(q, [], rcode=2)
        with self.assertRaises(DohError):
            decode_dns_response(servfail)

    def test_should_skip_doh_and_parse_doh_option(self) -> None:
        for skipped in (
            "127.0.0.1",
            "104.21.2.247",
            "::1",
            "[2606:4700::1]",
            "localhost",
            "LOCALHOST.",
            "dev.localhost",
            "printer.local",
        ):
            self.assertTrue(should_skip_doh(skipped), f"expected skip for {skipped}")

        for resolved in ("neruton.moer.eu.org", "example.com", "localhost.example.com"):
            self.assertFalse(should_skip_doh(resolved), f"expected DoH for {resolved}")

        self.assertEqual(parse_doh_option(True).mode, "auto")
        self.assertEqual(parse_doh_option(True).endpoints, DEFAULT_DOH_ENDPOINTS)
        self.assertEqual(parse_doh_option("auto").mode, "auto")
        self.assertEqual(parse_doh_option("strict").mode, "strict")
        self.assertEqual(parse_doh_option(False).mode, "off")
        self.assertEqual(parse_doh_option("off").mode, "off")
        custom = parse_doh_option("https://1.0.0.1/dns-query, https://8.8.4.4/dns-query")
        self.assertEqual(custom.endpoints, ("https://1.0.0.1/dns-query", "https://8.8.4.4/dns-query"))
        self.assertTrue(custom.custom)
        self.assertEqual(custom.mode, "strict")
        custom_list = parse_doh_option(["https://223.5.5.5/dns-query"])
        self.assertEqual(custom_list.endpoints, ("https://223.5.5.5/dns-query",))
        self.assertEqual(custom_list.mode, "strict")
        # Loopback http:// allowed for local testing; remote cleartext http:// rejected!
        self.assertEqual(
            parse_doh_option("http://127.0.0.1:8053/dns-query").endpoints,
            ("http://127.0.0.1:8053/dns-query",),
        )
        self.assertEqual(
            parse_doh_option("http://[::1]:8053/dns-query").endpoints,
            ("http://[::1]:8053/dns-query",),
        )
        self.assertEqual(
            parse_doh_option("http://localhost:8053/dns-query").endpoints,
            ("http://localhost:8053/dns-query",),
        )
        for bad_url in (
            "not-a-mode-or-url",
            "http://1.0.0.1/dns-query",
            "http://example.com/dns-query",
            "ftp://1.0.0.1/dns-query",
        ):
            with self.assertRaises(ValueError, msg=f"should reject {bad_url}"):
                parse_doh_option(bad_url)


class TestRFC6125CertHostnameVerification(unittest.TestCase):
    def test_dns_san_exact_wildcard_and_rejections(self) -> None:
        cert = {
            "subject": ((("commonName", "moer.eu.org"),),),
            "subjectAltName": (
                ("DNS", "moer.eu.org"),
                ("DNS", "*.moer.eu.org"),
                ("DNS", "api-*.staging.example.net"),
            ),
        }
        verify_cert_hostname(cert, "moer.eu.org")
        verify_cert_hostname(cert, "NERUTON.moer.eu.org.")
        verify_cert_hostname(cert, "api-v2.staging.example.net")

        for bad in (
            "a.b.moer.eu.org",  # wildcard matches only one label
            "other.eu.org",
            "web-v2.staging.example.net",
            "api-.staging.example.net",  # partial wildcard `*` must match >= 1 char
            "xn--foo.moer.eu.org",  # RFC 6125 forbids wildcard matching IDNA A-label
        ):
            with self.assertRaises(ssl.SSLCertVerificationError, msg=f"should reject {bad}"):
                verify_cert_hostname(cert, bad)

    def test_san_precedence_over_cn_and_cn_fallback(self) -> None:
        # When DNS SAN is present, CN MUST NOT be consulted even if CN matches!
        cert_with_san = {
            "subject": ((("commonName", "real.example.com"),),),
            "subjectAltName": (("DNS", "other.example.com"),),
        }
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_cert_hostname(cert_with_san, "real.example.com")

        # When ANY subjectAltName entry is present (even non-DNS like IP Address),
        # CN MUST NOT be consulted!
        cert_with_ip_san_only = {
            "subject": ((("commonName", "victim.example.com"),),),
            "subjectAltName": (("IP Address", "127.0.0.1"),),
        }
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_cert_hostname(cert_with_ip_san_only, "victim.example.com")

        # Cert SAN patterns with whitespace or trailing/leading dot MUST be rejected!
        for bad_san in (" example.com ", "example.com ", " example.com", "example.com.", ".example.com"):
            cert_bad_san = {"subjectAltName": (("DNS", bad_san),)}
            with self.assertRaises(ssl.SSLCertVerificationError, msg=f"should reject SAN {bad_san!r}"):
                verify_cert_hostname(cert_bad_san, "example.com")

        # When NO subjectAltName extension is present at all, CN fallback applies.
        cert_cn_only = {
            "subject": ((("commonName", "*.example.com"),),),
        }
        verify_cert_hostname(cert_cn_only, "app.example.com")
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_cert_hostname(cert_cn_only, "example.com")

    def test_rejects_broad_or_malformed_wildcards(self) -> None:
        for pat in ("*", "*.com", "a.*.example.com", "a*b*c.example.com", "xn--*.example.com"):
            cert = {"subjectAltName": (("DNS", pat),)}
            with self.assertRaises(ssl.SSLCertVerificationError, msg=f"should reject pattern {pat}"):
                verify_cert_hostname(cert, "a.b.example.com")

    def test_ip_san_matching_and_no_cn_fallback(self) -> None:
        cert = {
            "subject": ((("commonName", "10.0.0.1"),),),
            "subjectAltName": (
                ("IP Address", "127.0.0.1"),
                ("IP Address", "2606:4700:3032:0000:0000:0000:6815:02f7"),
            ),
        }
        verify_cert_hostname(cert, "127.0.0.1")
        verify_cert_hostname(cert, "2606:4700:3032::6815:2f7")
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_cert_hostname(cert, "10.0.0.1")  # CN ignored for IP literals
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_cert_hostname({}, "example.com")


class TestMockDohRaceFallbackAndStrict(unittest.IsolatedAsyncioTestCase):
    async def test_doh_race_cancels_slow_peer_and_parses_ech_and_chunked(self) -> None:
        ech_raw = _build_ech_config_list("cloudflare-ech.com")
        slow = _MockDohServer(ipv4=("10.0.0.1",), delay=5.0)
        fast = _MockDohServer(
            ipv4=("104.21.2.247",),
            ipv6=("2606:4700:3032::6815:2f7",),
            ech_bytes=ech_raw,
            ipv4_hints=("172.67.129.230",),
            chunked=True,
        )
        await slow.start()
        await fast.start()
        try:
            t0 = asyncio.get_running_loop().time()
            res = await resolve_doh(
                "neruton.moer.eu.org",
                endpoints=(slow.url, fast.url),
                timeout=3.0,
            )
            elapsed = asyncio.get_running_loop().time() - t0
            self.assertLess(elapsed, 1.5)
            self.assertEqual(res.endpoint, fast.url)
            self.assertEqual(res.ipv4, ("104.21.2.247", "172.67.129.230"))
            self.assertEqual(res.ipv6, ("2606:4700:3032::6815:2f7",))
            self.assertEqual(res.ech_config_list, ech_raw)
            self.assertEqual(parse_ech_public_name(res.ech_config_list or b""), "cloudflare-ech.com")
        finally:
            await slow.stop()
            await fast.stop()

    async def test_doh_fallback_to_third_endpoint(self) -> None:
        bad1 = _MockDohServer(status_code=500)
        bad2 = _MockDohServer(status_code=503)
        good3 = _MockDohServer(ipv4=("203.0.113.10",))
        await bad1.start()
        await bad2.start()
        await good3.start()
        try:
            res = await resolve_doh(
                "service.example.org",
                endpoints=(bad1.url, bad2.url, good3.url),
                timeout=2.0,
            )
            self.assertEqual(res.endpoint, good3.url)
            self.assertEqual(res.ips, ("203.0.113.10",))
        finally:
            await bad1.stop()
            await bad2.stop()
            await good3.stop()

    async def test_doh_auto_fallback_warns_and_strict_fails(self) -> None:
        bad = _MockDohServer(status_code=502)
        await bad.start()
        try:
            warnings: List[str] = []
            ips, doh_res, fell_back = await resolve_target_ips(
                "example.org",
                DohConfig(mode="auto", endpoints=(bad.url,), custom=True),
                doh_timeout=1.5,
                on_warn=warnings.append,
            )
            self.assertIsNone(ips)
            self.assertIsNone(doh_res)
            self.assertTrue(fell_back)
            self.assertEqual(len(warnings), 1)
            self.assertIn("falling back to system DNS", warnings[0])

            with self.assertRaises(DohError):
                await resolve_target_ips(
                    "example.org",
                    DohConfig(mode="strict", endpoints=(bad.url,), custom=True),
                    doh_timeout=1.5,
                )
        finally:
            await bad.stop()


class TestStealthTlsWireFragmentationAndSni(unittest.IsolatedAsyncioTestCase):
    def test_split_client_hello_splits_record_and_sni(self) -> None:
        ctx = ssl.create_default_context()
        in_bio = ssl.MemoryBIO()
        out_bio = ssl.MemoryBIO()
        sslobj = ctx.wrap_bio(in_bio, out_bio, server_side=False, server_hostname="neruton.moer.eu.org")
        with contextlib.suppress(ssl.SSLWantReadError):
            sslobj.do_handshake()
        ch = out_bio.read()
        self.assertIn(b"neruton.moer.eu.org", ch)

        chunks = split_client_hello(ch, sni_hint="neruton.moer.eu.org")
        self.assertGreaterEqual(len(chunks), 3)
        self.assertEqual(chunks[0], ch[:5])
        self.assertEqual(b"".join(chunks), ch)
        for seg in chunks:
            self.assertNotIn(b"neruton.moer.eu.org", seg)

        # Uppercase custom SNI must normalize AND still be split across segments!
        plan_upper = resolve_tls_plan(
            is_tls=True,
            real_host="real.example.test",
            sni_mode="auto",
            custom_sni="FRONT.EXAMPLE.COM",
        )
        self.assertEqual(plan_upper.wire_sni, "front.example.com")

        out_upper = ssl.MemoryBIO()
        obj_upper = ctx.wrap_bio(ssl.MemoryBIO(), out_upper, server_side=False, server_hostname="FRONT.EXAMPLE.COM")
        with contextlib.suppress(ssl.SSLWantReadError):
            obj_upper.do_handshake()
        ch_upper = out_upper.read()
        chunks_upper = split_client_hello(ch_upper, sni_hint="FRONT.EXAMPLE.COM")
        self.assertGreaterEqual(len(chunks_upper), 3)
        self.assertEqual(b"".join(chunks_upper), ch_upper)
        for seg in chunks_upper:
            self.assertNotIn(b"front.example.com", seg.lower())

    async def test_legacy_websockets_12_fails_fast_on_manual_sni_check(self) -> None:
        import neruton.client as client_mod

        with mock.patch.object(client_mod, "_HAS_MODERN_WS", False):
            for mode, custom in (("none", None), ("auto", "front.example.test")):
                with self.assertRaises(TunnelError) as cm:
                    await _open_websocket(
                        "wss://neruton.moer.eu.org/_neruton/tunnel",
                        token="ntk_never_sent",
                        no_tls_verify=False,
                        sni_mode=mode,
                        sni=custom,
                    )
                self.assertIn("websockets>=13", str(cm.exception))

    async def test_client_hello_tcp_fragmentation_on_real_local_socket(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl CLI not available")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cert_file, key_file = _generate_self_signed_cert(
                tmp_path,
                cn="neruton.example.test",
                san_dns=("neruton.example.test", "*.example.test"),
            )

            server_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ssl.load_cert_chain(str(cert_file), str(key_file))
            observed_sni: List[Optional[str]] = []

            def _sni_cb(_sock: Any, server_name: Optional[str], _ctx: ssl.SSLContext) -> None:
                observed_sni.append(server_name)

            server_ssl.sni_callback = _sni_cb

            # Raw TCP TLS server using ssl.MemoryBIO so we can inspect the EXACT TCP
            # segments received on the wire before TLS reassembly!
            received_ch_segments: List[bytes] = []
            handshake_complete = asyncio.Event()

            async def _raw_tls_server(
                reader: asyncio.StreamReader, writer: asyncio.StreamWriter
            ) -> None:
                try:
                    in_bio = ssl.MemoryBIO()
                    out_bio = ssl.MemoryBIO()
                    sslobj = server_ssl.wrap_bio(in_bio, out_bio, server_side=True)
                    while True:
                        chunk = await reader.read(4096)
                        if not chunk:
                            return
                        received_ch_segments.append(chunk)
                        in_bio.write(chunk)
                        try:
                            sslobj.do_handshake()
                        except ssl.SSLWantReadError:
                            out = out_bio.read()
                            if out:
                                writer.write(out)
                                await writer.drain()
                            continue
                        out = out_bio.read()
                        if out:
                            writer.write(out)
                            await writer.drain()
                        handshake_complete.set()
                        # Echo one TLS app message to confirm post-handshake passthrough.
                        while True:
                            try:
                                app = sslobj.read(4096)
                                sslobj.write(b"pong:" + app)
                                writer.write(out_bio.read())
                                await writer.drain()
                                break
                            except ssl.SSLWantReadError:
                                more = await reader.read(4096)
                                if not more:
                                    return
                                in_bio.write(more)
                        break
                finally:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()

            tcp_srv = await asyncio.start_server(_raw_tls_server, "127.0.0.1", 0)
            srv_port = int(tcp_srv.sockets[0].getsockname()[1])
            try:
                client_ssl = ssl.create_default_context(cafile=str(cert_file))
                plan = resolve_tls_plan(
                    is_tls=True,
                    real_host="neruton.example.test",
                    sni_mode="auto",
                )
                self.assertTrue(plan.fragment_client_hello)
                self.assertEqual(plan.effective_sni_mode, "fragment")

                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                loop = asyncio.get_running_loop()
                await loop.sock_connect(sock, ("127.0.0.1", srv_port))

                received_app = bytearray()
                app_done = asyncio.Event()

                class _EchoClientProto(asyncio.Protocol):
                    def data_received(self, data: bytes) -> None:
                        received_app.extend(data)
                        if received_app.startswith(b"pong:"):
                            app_done.set()

                proto = _EchoClientProto()
                tls_transport, fragmented, frag_count, tls_ver = await upgrade_transport_tls(
                    sock,
                    proto,
                    plan,
                    ssl_context=build_stealth_ssl_context(plan, base_ssl_context=client_ssl),
                    handshake_timeout=5.0,
                    fragment_delay=0.015,  # 15ms guarantees separate TCP segments on loopback
                )
                try:
                    self.assertTrue(fragmented)
                    self.assertGreaterEqual(frag_count, 3)
                    self.assertIsNotNone(tls_ver)
                    await asyncio.wait_for(handshake_complete.wait(), timeout=3.0)

                    # Verify the raw TCP server actually received split TCP segments!
                    self.assertGreaterEqual(len(received_ch_segments), 2)
                    for seg in received_ch_segments:
                        self.assertNotIn(b"neruton.example.test", seg)
                    self.assertEqual(observed_sni, ["neruton.example.test"])

                    # Verify application traffic flows cleanly in passthrough mode.
                    tls_transport.write(b"hello-stealth")
                    await asyncio.wait_for(app_done.wait(), timeout=3.0)
                    self.assertEqual(bytes(received_app), b"pong:hello-stealth")
                finally:
                    tls_transport.close()
            finally:
                tcp_srv.close()
                await tcp_srv.wait_closed()

    async def test_omitted_and_custom_sni_with_strict_rfc6125_over_wss_and_doh(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl CLI not available")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            good_cert, good_key = _generate_self_signed_cert(
                tmp_path,
                cn="real.example.test",
                san_dns=("real.example.test", "*.example.test"),
            )
            wrong_cert, wrong_key = _generate_self_signed_cert(
                tmp_path,
                cn="wrong.other.test",
                san_dns=("wrong.other.test",),
            )

            doh_srv = _MockDohServer(ipv4=("127.0.0.1",))
            await doh_srv.start()

            async def _run_wss_case(
                cert_file: Path,
                key_file: Path,
                *,
                sni_mode: str,
                custom_sni: Optional[str] = None,
                no_tls_verify: bool = False,
            ) -> Tuple[Optional[str], List[Optional[str]], List[str]]:
                srv_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                srv_ssl.load_cert_chain(str(cert_file), str(key_file))
                seen_sni: List[Optional[str]] = []
                seen_auth: List[str] = []

                def _sni_cb(_sock: Any, name: Optional[str], _ctx: ssl.SSLContext) -> None:
                    seen_sni.append(name)

                srv_ssl.sni_callback = _sni_cb

                def _proc(_conn: ServerConnection, request: Any) -> Optional[WsHttpResponse]:
                    auth = request.headers.get("Authorization")
                    if auth:
                        seen_auth.append(auth)
                    return None

                async def _ws_handler(ws: ServerConnection) -> None:
                    await ws.send("ok")
                    await ws.close()

                ws_srv = await serve(
                    _ws_handler,
                    "127.0.0.1",
                    0,
                    ssl=srv_ssl,
                    process_request=_proc,
                    compression=None,
                )
                ws_port = int(ws_srv.sockets[0].getsockname()[1])
                try:
                    client_ca = ssl.create_default_context(cafile=str(cert_file))
                    ws, info = await _open_websocket(
                        f"wss://real.example.test:{ws_port}/_neruton/tunnel",
                        token="ntk_secret_token",
                        no_tls_verify=no_tls_verify,
                        doh_config=DohConfig(mode="strict", endpoints=(doh_srv.url,), custom=True),
                        sni_mode=sni_mode,
                        sni=custom_sni,
                        base_ssl_context=client_ca,
                    )
                    try:
                        msg = await ws.recv()
                        self.assertEqual(msg, "ok")
                        return info.summary(), seen_sni, seen_auth
                    finally:
                        await ws.close()
                finally:
                    ws_srv.close()
                    await ws_srv.wait_closed()

            try:
                # 1. Omitted SNI (`none`) with valid cert for real.example.test -> PASSES!
                summary_none, sni_none, auth_none = await _run_wss_case(
                    good_cert, good_key, sni_mode="none"
                )
                self.assertIsNotNone(summary_none)
                self.assertEqual(sni_none, [None])
                self.assertEqual(auth_none, ["Bearer ntk_secret_token"])

                # 2. Custom SNI (`front.example.test`) + auto fragmentation with valid real cert -> PASSES!
                summary_custom, sni_custom, auth_custom = await _run_wss_case(
                    good_cert, good_key, sni_mode="auto", custom_sni="front.other.test"
                )
                self.assertIn("ClientHello fragmented", summary_custom or "")
                self.assertEqual(sni_custom, ["front.other.test"])
                self.assertEqual(auth_custom, ["Bearer ntk_secret_token"])

                # 3. Omitted SNI against WRONG cert -> MUST fail RFC 6125 BEFORE sending Bearer token!
                srv_ssl_bad = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                srv_ssl_bad.load_cert_chain(str(wrong_cert), str(wrong_key))
                leaked_auth: List[str] = []

                def _proc_bad(_conn: ServerConnection, request: Any) -> Optional[WsHttpResponse]:
                    auth = request.headers.get("Authorization")
                    if auth:
                        leaked_auth.append(auth)
                    return None

                async def _ws_noop(ws: ServerConnection) -> None:
                    await ws.close()

                ws_srv_bad = await serve(
                    _ws_noop, "127.0.0.1", 0, ssl=srv_ssl_bad, process_request=_proc_bad
                )
                bad_port = int(ws_srv_bad.sockets[0].getsockname()[1])
                try:
                    ca_bad = ssl.create_default_context(cafile=str(wrong_cert))
                    with self.assertRaises(TunnelConnectionError) as cm:
                        await _open_websocket(
                            f"wss://real.example.test:{bad_port}/_neruton/tunnel",
                            token="ntk_never_leak",
                            no_tls_verify=False,
                            doh_config=DohConfig(mode="strict", endpoints=(doh_srv.url,), custom=True),
                            sni_mode="none",
                            base_ssl_context=ca_bad,
                        )
                    self.assertIn("doesn't match", str(cm.exception))
                    # Bearer token MUST NEVER have been sent over an unverified TLS connection!
                    self.assertEqual(leaked_auth, [])
                finally:
                    ws_srv_bad.close()
                    await ws_srv_bad.wait_closed()

                # 4. Same wrong cert with no_tls_verify=True -> explicitly allowed
                _sum, _sni, auth_noverify = await _run_wss_case(
                    wrong_cert, wrong_key, sni_mode="none", no_tls_verify=True
                )
                self.assertEqual(auth_noverify, ["Bearer ntk_secret_token"])
            finally:
                await doh_srv.stop()

    async def test_ech_mode_fails_fast_with_clear_tunnel_error(self) -> None:
        # Without ECHConfigList, sni_mode="ech" fails fast with a clear TunnelError.
        with self.assertRaises(TunnelError) as cm1:
            resolve_tls_plan(is_tls=True, real_host="neruton.moer.eu.org", sni_mode="ech")
        msg = str(cm1.exception)
        self.assertIn("ech", msg.lower())
        self.assertIn("echconfiglist", msg.lower())

        # With ECHConfigList, both auto and ech plans enable TRUE TLS 1.3 ECH!
        ech_raw = _build_ech_config_list("cloudflare-ech.com")
        plan_auto = resolve_tls_plan(
            is_tls=True,
            real_host="neruton.moer.eu.org",
            sni_mode="auto",
            ech_config_list=ech_raw,
        )
        self.assertTrue(plan_auto.use_ech)
        self.assertEqual(plan_auto.effective_sni_mode, "ech")
        self.assertEqual(plan_auto.wire_sni, "cloudflare-ech.com")
        self.assertTrue(plan_auto.allow_ech_fallback)

        plan_strict = resolve_tls_plan(
            is_tls=True,
            real_host="neruton.moer.eu.org",
            sni_mode="ech",
            ech_config_list=ech_raw,
        )
        self.assertTrue(plan_strict.use_ech)
        self.assertFalse(plan_strict.allow_ech_fallback)

        # Tunnel.start() with retry_initial=True MUST fail fast when sni_mode="ech" has no ECH config!
        tunnel = Tunnel(
            target_url="http://127.0.0.1:3000",
            server="https://neruton.moer.eu.org",
            doh="off",
            sni_mode="ech",
            retry_initial=True,
        )
        with self.assertRaises(TunnelError):
            await tunnel.start()
        self.assertTrue(tunnel.closed)

        # Invalid base64 --ech-config also fails fast with TunnelError.
        tunnel_bad_b64 = Tunnel(
            target_url="http://127.0.0.1:3000",
            server="https://neruton.moer.eu.org",
            doh="off",
            sni_mode="ech",
            ech_config="not!valid!base64!",
            retry_initial=True,
        )
        with self.assertRaises(TunnelError):
            await tunnel_bad_b64.start()
        self.assertTrue(tunnel_bad_b64.closed)

        # CLI fails fast with exit code 1 when sni_mode="ech" has no ECH config (no DoH, no --ech-config).
        def _run_cli_ech() -> Tuple[int, str]:
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                rc = cli_main(
                    [
                        "http",
                        "3000",
                        "--server",
                        "https://neruton.moer.eu.org",
                        "--no-doh",
                        "--sni-mode",
                        "ech",
                    ]
                )
            return rc, err_buf.getvalue()

        rc, stderr_out = await asyncio.to_thread(_run_cli_ech)
        self.assertEqual(rc, 1)
        self.assertIn("ECH", stderr_out)

    async def test_cancel_during_fragmented_handshake_leaks_no_fds_or_tasks(self) -> None:
        # Silent TCP server that accepts a connection, waits for client EOF, and never replies.
        eof_seen = asyncio.Event()

        async def _stall_server(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while await reader.read(1024):
                    pass
                eof_seen.set()
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

        tcp_srv = await asyncio.start_server(_stall_server, "127.0.0.1", 0)
        port = int(tcp_srv.sockets[0].getsockname()[1])
        try:
            tasks_before = len(asyncio.all_tasks())
            plan = resolve_tls_plan(
                is_tls=True,
                real_host="stall.example.test",
                sni_mode="fragment",
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            loop = asyncio.get_running_loop()
            await loop.sock_connect(sock, ("127.0.0.1", port))

            task = asyncio.create_task(
                upgrade_transport_tls(
                    sock,
                    asyncio.Protocol(),
                    plan,
                    ssl_context=build_stealth_ssl_context(plan),
                    handshake_timeout=10.0,
                    fragment_delay=0.2,
                )
            )
            await asyncio.sleep(0.03)  # mid-fragmentation timer pending
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            # Cancelling must immediately close the socket so server observes EOF promptly!
            await asyncio.wait_for(eof_seen.wait(), timeout=1.0)
            await asyncio.sleep(0.03)
            self.assertEqual(sock.fileno(), -1)
            self.assertEqual(len(asyncio.all_tasks()), tasks_before)
        finally:
            tcp_srv.close()
            await tcp_srv.wait_closed()


class TestStealthConfigEnvAndCliPrecedence(unittest.TestCase):
    def test_config_toml_roundtrip_and_string_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "config.toml"
            save_config(
                Config(
                    server="https://neruton.moer.eu.org",
                    token="ntk_abc",
                    doh="strict",
                    sni_mode="fragment",
                    sni="moer.eu.org",
                    ech_config="AEX+DQ==",
                ),
                cfg_file,
            )
            loaded = load_config(cfg_file)
            self.assertEqual(loaded.doh, "strict")
            self.assertEqual(loaded.sni_mode, "fragment")
            self.assertEqual(loaded.sni, "moer.eu.org")
            self.assertEqual(loaded.ech_config, "AEX+DQ==")

            # Non-string TOML value (e.g. boolean) must be rejected for Rust/Node compat
            cfg_file.write_text("doh = true\n", encoding="utf-8")
            with self.assertRaises(NerutonError):
                load_config(cfg_file)

    def test_precedence_explicit_gt_env_gt_config_gt_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_file = Path(tmp) / "config.toml"

            # 1. Defaults when no file & no env
            with mock.patch.dict(os.environ, {}, clear=True):
                opts = resolve_stealth_options(config_file=cfg_file)
                self.assertEqual(opts.doh.mode, "auto")
                self.assertEqual(opts.sni_mode, "auto")
                self.assertIsNone(opts.sni)
                self.assertIsNone(opts.ech_config)

            # 2. config.toml overrides defaults
            save_config(
                doh="strict",
                sni_mode="none",
                sni="cfg.example",
                ech_config="CFG_ECH",
                path=cfg_file,
            )
            with mock.patch.dict(os.environ, {}, clear=True):
                opts = resolve_stealth_options(config_file=cfg_file)
                self.assertEqual(opts.doh.mode, "strict")
                self.assertEqual(opts.sni_mode, "none")
                self.assertEqual(opts.sni, "cfg.example")
                self.assertEqual(opts.ech_config, "CFG_ECH")

            # 3. Env vars override config.toml
            with mock.patch.dict(
                os.environ,
                {
                    "NERUTON_DOH": "https://223.5.5.5/dns-query",
                    "NERUTON_SNI_MODE": "fragment",
                    "NERUTON_SNI": "env.example",
                    "NERUTON_ECH_CONFIG": "ENV_ECH",
                },
                clear=True,
            ):
                opts = resolve_stealth_options(config_file=cfg_file)
                self.assertEqual(opts.doh.endpoints, ("https://223.5.5.5/dns-query",))
                self.assertEqual(opts.sni_mode, "fragment")
                self.assertEqual(opts.sni, "env.example")
                self.assertEqual(opts.ech_config, "ENV_ECH")

                # 4. Explicit args (including falsy doh=False!) override env & config.toml
                opts2 = resolve_stealth_options(
                    doh=False,
                    sni_mode="plain",
                    sni="arg.example",
                    ech_config="ARG_ECH",
                    config_file=cfg_file,
                )
                self.assertEqual(opts2.doh.mode, "off")
                self.assertEqual(opts2.sni_mode, "plain")
                self.assertEqual(opts2.sni, "arg.example")
                self.assertEqual(opts2.ech_config, "ARG_ECH")

    def test_cli_flags_and_config_set_show(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "tunnel",
                "--url",
                "3000",
                "--doh",
                "strict",
                "--sni-mode",
                "fragment",
                "--sni",
                "moer.eu.org",
                "--ech-config",
                "AAAA",
            ]
        )
        self.assertEqual(args.doh, "strict")
        self.assertFalse(args.no_doh)
        self.assertEqual(args.sni_mode, "fragment")
        self.assertEqual(args.sni, "moer.eu.org")
        self.assertEqual(args.ech_config, "AAAA")

        http_args = parser.parse_args(["http", "8080", "--no-doh", "--sni-mode", "plain"])
        self.assertTrue(http_args.no_doh)
        self.assertEqual(http_args.sni_mode, "plain")

        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.toml"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli_main(
                    [
                        "config",
                        "set",
                        "--doh",
                        "https://1.0.0.1/dns-query",
                        "--sni-mode",
                        "fragment",
                        "--sni",
                        "moer.eu.org",
                        "--ech-config",
                        "TEST_ECH",
                        "--config",
                        str(cfg_path),
                    ]
                )
            self.assertEqual(rc, 0)

            buf = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True):
                with contextlib.redirect_stdout(buf):
                    rc = cli_main(["config", "show", "--config", str(cfg_path)])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("https://1.0.0.1/dns-query", out)
            self.assertIn("fragment", out)
            self.assertIn("moer.eu.org", out)
            self.assertIn("<configured>", out)

            # `config set --no-doh` sets `doh = "off"` and rejects mutual exclusion
            buf_nodoh = io.StringIO()
            with contextlib.redirect_stdout(buf_nodoh):
                rc_nodoh = cli_main(["config", "set", "--no-doh", "--config", str(cfg_path)])
            self.assertEqual(rc_nodoh, 0)
            self.assertEqual(load_config(cfg_path).doh, "off")

            err_cfg_bad = io.StringIO()
            with contextlib.redirect_stderr(err_cfg_bad):
                rc_cfg_bad = cli_main(
                    ["config", "set", "--doh", "auto", "--no-doh", "--config", str(cfg_path)]
                )
            self.assertEqual(rc_cfg_bad, 1)
            self.assertIn("--no-doh", err_cfg_bad.getvalue())

            # Mutual exclusion of --doh and --no-doh on `http`
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                rc_bad = cli_main(["http", "3000", "--doh", "strict", "--no-doh"])
            self.assertEqual(rc_bad, 1)
            self.assertIn("--no-doh", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
