"""Comprehensive unit & mock-server tests for pure-Python TLS 1.3 + RFC 9849 ECH."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import datetime
import ipaddress
import os
import socket
import ssl
import struct
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.x509.verification import Store

from neruton.client import _open_websocket
from neruton.doh import DNS_TYPE_A, DNS_TYPE_HTTPS, DohConfig
from neruton.errors import AuthError, TunnelError
from neruton.tls_stealth import TransportInfo
from neruton.hpke import (
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
    KEM_DHKEM_P256_HKDF_SHA256,
    KEM_DHKEM_X25519_HKDF_SHA256,
    KDF_HKDF_SHA256,
    encode_ech_config,
    encode_ech_config_list,
    select_ech_config,
    setup_base_r,
    setup_base_s,
)
from neruton.tls13_ech import (
    ALERT_ECH_REQUIRED,
    ALERT_LEVEL_FATAL,
    CIPHER_SUITES,
    CONTENT_ALERT,
    CONTENT_APPLICATION_DATA,
    CONTENT_CHANGE_CIPHER_SPEC,
    CONTENT_HANDSHAKE,
    ECH_CLIENT_HELLO_INNER,
    ECH_CLIENT_HELLO_OUTER,
    EXT_ALPN,
    EXT_COOKIE,
    EXT_ENCRYPTED_CLIENT_HELLO,
    EXT_KEY_SHARE,
    EXT_SERVER_NAME,
    EXT_SUPPORTED_VERSIONS,
    GROUP_SECP256R1,
    GROUP_X25519,
    HRR_RANDOM,
    HS_CERTIFICATE,
    HS_CERTIFICATE_VERIFY,
    HS_CLIENT_HELLO,
    HS_ENCRYPTED_EXTENSIONS,
    HS_FINISHED,
    HS_KEY_UPDATE,
    HS_MESSAGE_HASH,
    HS_NEW_SESSION_TICKET,
    HS_SERVER_HELLO,
    MAX_PLAINTEXT_RECORD_LEN,
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ED25519,
    SIG_RSA_PSS_RSAE_SHA256,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_VERSION_1_2,
    TLS_VERSION_1_3,
    EchRejectedError,
    TlsAlertError,
    TlsError,
    TlsRecordCipher,
    _pack_ext,
    _pack_handshake,
    _pack_plaintext_record,
    _u24_pack,
    _u24_unpack,
    build_ech_client_hello_pair,
    compute_app_secrets,
    compute_ech_accept_confirmation,
    compute_handshake_secrets,
    compute_hrr_ech_accept_confirmation,
    connect_tls13_ech,
    derive_finished_verify_data,
    hash_bytes,
    pad_encoded_client_hello_inner,
    verify_server_certificate_chain,
)


# ---------------------------------------------------------------------------
# X.509 Test PKI Helpers
# ---------------------------------------------------------------------------


def _build_ca(
    cn: str = "Neruton Test Root CA",
    *,
    is_ca: bool = True,
    not_before_offset_hours: int = -2,
    not_after_offset_hours: int = 24,
) -> Tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    now = datetime.datetime.now(datetime.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(hours=not_before_offset_hours))
        .not_valid_after(now + datetime.timedelta(hours=not_after_offset_hours))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    return key, builder.sign(key, hashes.SHA256())


def _build_leaf(
    issuer_key: ec.EllipticCurvePrivateKey,
    issuer_cert: x509.Certificate,
    *,
    cn: str,
    san_dns: Sequence[str] = (),
    san_ips: Sequence[str] = (),
    key_kind: str = "ecdsa_p256",
    not_before_offset_hours: int = -1,
    not_after_offset_hours: int = 24,
    include_server_auth_eku: bool = True,
) -> Tuple[Any, x509.Certificate, int]:
    now = datetime.datetime.now(datetime.timezone.utc)
    if key_kind == "ecdsa_p256":
        leaf_key: Any = ec.generate_private_key(ec.SECP256R1())
        sig_scheme = SIG_ECDSA_SECP256R1_SHA256
    elif key_kind == "ecdsa_p384":
        leaf_key = ec.generate_private_key(ec.SECP384R1())
        sig_scheme = SIG_ECDSA_SECP384R1_SHA384
    elif key_kind == "rsa":
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        sig_scheme = SIG_RSA_PSS_RSAE_SHA256
    elif key_kind == "ed25519":
        leaf_key = ed25519.Ed25519PrivateKey.generate()
        sig_scheme = SIG_ED25519
    else:
        raise ValueError(key_kind)

    sans: List[x509.GeneralName] = [x509.DNSName(d) for d in san_dns]
    sans.extend(x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(hours=not_before_offset_hours))
        .not_valid_after(now + datetime.timedelta(hours=not_after_offset_hours))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    if include_server_auth_eku:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    cert = builder.sign(issuer_key, hashes.SHA256())
    return leaf_key, cert, sig_scheme


def _ssl_context_for_ca(ca_cert: x509.Certificate) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca_cert.public_bytes(Encoding.PEM).decode("ascii"))
    return ctx


def _make_ech_keypair(
    kem_id: int = KEM_DHKEM_X25519_HKDF_SHA256,
    *,
    config_id: int = 42,
    public_name: str = "public-outer.example.test",
    aead_id: int = AEAD_AES_128_GCM,
) -> Tuple[bytes, bytes, bytes]:
    """Return ``(sk_r_bytes, raw_ech_config, ech_config_list_bytes)``."""
    if kem_id == KEM_DHKEM_X25519_HKDF_SHA256:
        sk = x25519.X25519PrivateKey.generate()
        sk_bytes = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        pk_bytes = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    else:
        sk_ec = ec.generate_private_key(ec.SECP256R1())
        sk_bytes = sk_ec.private_numbers().private_value.to_bytes(32, "big")
        pk_bytes = sk_ec.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    raw_cfg = encode_ech_config(
        config_id=config_id,
        kem_id=kem_id,
        public_key=pk_bytes,
        cipher_suites=[(KDF_HKDF_SHA256, aead_id)],
        maximum_name_length=64,
        public_name=public_name,
    )
    return sk_bytes, raw_cfg, encode_ech_config_list([raw_cfg])


# ---------------------------------------------------------------------------
# In-process RFC 8446 + RFC 9849 Mock TLS 1.3 ECH Server
# ---------------------------------------------------------------------------


def _parse_ch_fields(body: bytes) -> Tuple[bytes, bytes, Dict[int, bytes], Dict[int, Tuple[int, int]]]:
    """Parse ClientHello body (no 4B header) -> ``(random, session_id, exts, ext_spans)``."""
    pos = 2  # legacy_version
    rand = body[pos : pos + 32]
    pos += 32
    sid_len = body[pos]
    pos += 1
    sid = body[pos : pos + sid_len]
    pos += sid_len
    (cs_len,) = struct.unpack_from("!H", body, pos)
    pos += 2 + cs_len
    comp_len = body[pos]
    pos += 1 + comp_len
    (ext_len,) = struct.unpack_from("!H", body, pos)
    pos += 2
    ext_end = pos + ext_len
    exts: Dict[int, bytes] = {}
    spans: Dict[int, Tuple[int, int]] = {}
    while pos < ext_end:
        et, el = struct.unpack_from("!HH", body, pos)
        pos += 4
        exts[et] = body[pos : pos + el]
        spans[et] = (pos, pos + el)
        pos += el
    return rand, sid, exts, spans


def _extract_sni_from_ext(sni_ext: bytes) -> Optional[str]:
    if len(sni_ext) < 5:
        return None
    nlen = struct.unpack_from("!H", sni_ext, 3)[0]
    return sni_ext[5 : 5 + nlen].decode("ascii")


def _extract_client_key_shares(ks_ext: bytes) -> Dict[int, bytes]:
    (list_len,) = struct.unpack_from("!H", ks_ext, 0)
    pos = 2
    out: Dict[int, bytes] = {}
    while pos < 2 + list_len:
        grp, klen = struct.unpack_from("!HH", ks_ext, pos)
        pos += 4
        out[grp] = ks_ext[pos : pos + klen]
        pos += klen
    return out


def _sign_cert_verify(priv_key: Any, scheme: int, th: bytes) -> bytes:
    content = (b"\x20" * 64) + b"TLS 1.3, server CertificateVerify\x00" + th
    if scheme == SIG_ECDSA_SECP256R1_SHA256:
        sig = priv_key.sign(content, ec.ECDSA(hashes.SHA256()))
    elif scheme == SIG_ECDSA_SECP384R1_SHA384:
        sig = priv_key.sign(content, ec.ECDSA(hashes.SHA384()))
    elif scheme == SIG_RSA_PSS_RSAE_SHA256:
        sig = priv_key.sign(
            content,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            hashes.SHA256(),
        )
    elif scheme == SIG_ED25519:
        sig = priv_key.sign(content)
    else:
        raise ValueError(scheme)
    return struct.pack("!HH", scheme, len(sig)) + sig


def _encode_cert_message(certs: Sequence[x509.Certificate]) -> bytes:
    entries = bytearray()
    for c in certs:
        der = c.public_bytes(Encoding.DER)
        entries.extend(_u24_pack(len(der)) + der + b"\x00\x00")
    return b"\x00" + _u24_pack(len(entries)) + bytes(entries)


@dataclass
class _MockEchServerConfig:
    ech_sk_bytes: bytes
    ech_raw_config: bytes
    ech_kem_id: int
    ech_config_id: int
    inner_key: Any
    inner_cert: x509.Certificate
    inner_sig_scheme: int
    outer_key: Any
    outer_cert: x509.Certificate
    outer_sig_scheme: int
    retry_configs_on_reject: Optional[bytes] = None
    cipher_suite: int = TLS_AES_128_GCM_SHA256
    require_hrr_group: Optional[int] = None
    require_hrr_cookie: Optional[bytes] = None
    send_ccs: bool = True
    fragment_server_flight: bool = False
    send_new_session_ticket: bool = False
    send_key_update: Optional[int] = None  # 0 or 1
    tamper_cert_verify: bool = False
    tamper_server_finished: bool = False
    force_reject_ech: bool = False
    extra_padding_bytes: int = 0
    http_401_json: Optional[str] = None
    coalesce_plaintext_flight_with_sh: bool = False
    hrr_illegal_reply_group: Optional[int] = None
    extra_sh_extensions: Tuple[Tuple[int, bytes], ...] = ()
    extra_hrr_extensions: Tuple[Tuple[int, bytes], ...] = ()
    ee_alpn: Optional[str] = None


class _MockTls13EchServer:
    """Real RFC 8446 + RFC 9849 mock TLS 1.3 ECH server on TCP loopback."""

    def __init__(self, cfg: _MockEchServerConfig) -> None:
        self.cfg = cfg
        self._server: Optional[asyncio.AbstractServer] = None
        self.port = 0
        self.connections = 0
        self.observed_outer_snis: List[Optional[str]] = []
        self.observed_inner_snis: List[Optional[str]] = []
        self.observed_alerts: List[Tuple[int, int]] = []
        self.observed_app_bytes: List[bytes] = []
        self.ech_accepted_history: List[bool] = []

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _read_record(self, reader: asyncio.StreamReader) -> Tuple[int, bytes, bytes]:
        hdr = await reader.readexactly(5)
        rtype, _ver, rlen = struct.unpack("!BHH", hdr)
        body = await reader.readexactly(rlen)
        return rtype, hdr, body

    def _try_decrypt_ech(
        self,
        ch_body: bytes,
        ch_exts: Dict[int, bytes],
        ch_spans: Dict[int, Tuple[int, int]],
        outer_sid: bytes,
        opener: Any,
    ) -> Tuple[bool, Any, Optional[bytes], Optional[bytes], Optional[str], Optional[Dict[int, bytes]]]:
        """Attempt RFC 9849 ECH decryption -> ``(ok, opener, logical_inner_msg, inner_rand, inner_sni, inner_exts)``."""
        if self.cfg.force_reject_ech:
            return False, opener, None, None, None, None
        ech_ext = ch_exts.get(EXT_ENCRYPTED_CLIENT_HELLO)
        if not ech_ext or ech_ext[0] != ECH_CLIENT_HELLO_OUTER:
            return False, opener, None, None, None, None
        kdf_id, aead_id, cfg_id = struct.unpack_from("!HHB", ech_ext, 1)
        pos = 6
        (enc_len,) = struct.unpack_from("!H", ech_ext, pos)
        pos += 2
        enc = ech_ext[pos : pos + enc_len]
        pos += enc_len
        (payload_len,) = struct.unpack_from("!H", ech_ext, pos)
        pos += 2
        payload = ech_ext[pos : pos + payload_len]
        if cfg_id != self.cfg.ech_config_id:
            return False, opener, None, None, None, None

        # Reconstruct ClientHelloOuterAAD by zeroing payload bytes inside ch_body
        ext_start, _ext_end = ch_spans[EXT_ENCRYPTED_CLIENT_HELLO]
        payload_start = ext_start + pos
        aad = bytearray(ch_body)
        aad[payload_start : payload_start + payload_len] = b"\x00" * payload_len

        try:
            if opener is None:
                info = b"tls ech\x00" + self.cfg.ech_raw_config
                opener = setup_base_r(
                    self.cfg.ech_kem_id,
                    kdf_id,
                    aead_id,
                    enc,
                    self.cfg.ech_sk_bytes,
                    info,
                )
            padded_inner = opener.open(bytes(aad), payload)
        except Exception:
            return False, opener, None, None, None, None

        # Parse EncodedClientHelloInner (strip trailing padding after extensions)
        ipos = 2 + 32
        isid_len = padded_inner[ipos]
        assert isid_len == 0
        ipos += 1
        (ics_len,) = struct.unpack_from("!H", padded_inner, ipos)
        ipos += 2 + ics_len
        icomp_len = padded_inner[ipos]
        ipos += 1 + icomp_len
        (iext_len,) = struct.unpack_from("!H", padded_inner, ipos)
        inner_body_end = ipos + 2 + iext_len
        unpadded_inner = padded_inner[:inner_body_end]

        # Reconstruct logical ClientHelloInner by inserting outer_sid
        logical_inner_body = (
            unpadded_inner[:34]
            + bytes([len(outer_sid)])
            + outer_sid
            + unpadded_inner[35:]
        )
        logical_inner_msg = _pack_handshake(HS_CLIENT_HELLO, logical_inner_body)
        inner_rand, _sid, inner_exts, _ = _parse_ch_fields(logical_inner_body)
        assert inner_exts.get(EXT_ENCRYPTED_CLIENT_HELLO) == bytes([ECH_CLIENT_HELLO_INNER])
        inner_sni = _extract_sni_from_ext(inner_exts[EXT_SERVER_NAME]) if EXT_SERVER_NAME in inner_exts else None
        return True, opener, logical_inner_msg, inner_rand, inner_sni, inner_exts

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            spec = CIPHER_SUITES[self.cfg.cipher_suite]
            rtype, _hdr, ch1_rec = await self._read_record(reader)
            if rtype != CONTENT_HANDSHAKE or ch1_rec[0] != HS_CLIENT_HELLO:
                return
            ch1_body = ch1_rec[4:]
            _outer_rand, outer_sid, outer_exts, outer_spans = _parse_ch_fields(ch1_body)
            self.observed_outer_snis.append(
                _extract_sni_from_ext(outer_exts[EXT_SERVER_NAME])
                if EXT_SERVER_NAME in outer_exts
                else None
            )

            ech_ok, opener, inner_ch1_msg, inner_rand, inner_sni, inner_exts = self._try_decrypt_ech(
                ch1_body, outer_exts, outer_spans, outer_sid, None
            )
            if ech_ok:
                self.observed_inner_snis.append(inner_sni)

            active_ch1_msg = inner_ch1_msg if ech_ok and inner_ch1_msg is not None else ch1_rec
            active_exts = inner_exts if ech_ok and inner_exts is not None else outer_exts
            transcript = bytearray(active_ch1_msg)

            # Optional HelloRetryRequest
            if self.cfg.require_hrr_group is not None or self.cfg.require_hrr_cookie is not None:
                hrr_exts: List[Tuple[int, bytes]] = [
                    (EXT_SUPPORTED_VERSIONS, struct.pack("!H", TLS_VERSION_1_3))
                ]
                if self.cfg.require_hrr_group is not None:
                    hrr_exts.append((EXT_KEY_SHARE, struct.pack("!H", self.cfg.require_hrr_group)))
                if self.cfg.require_hrr_cookie is not None:
                    ck = self.cfg.require_hrr_cookie
                    hrr_exts.append((EXT_COOKIE, struct.pack("!H", len(ck)) + ck))
                hrr_exts.extend(self.cfg.extra_hrr_extensions)
                if ech_ok:
                    hrr_exts.append((EXT_ENCRYPTED_CLIENT_HELLO, b"\x00" * 8))

                ext_wire = b"".join(_pack_ext(t, v) for t, v in hrr_exts)
                hrr_body = (
                    struct.pack("!H", TLS_VERSION_1_2)
                    + HRR_RANDOM
                    + bytes([len(outer_sid)])
                    + outer_sid
                    + struct.pack("!HB", self.cfg.cipher_suite, 0)
                    + struct.pack("!H", len(ext_wire))
                    + ext_wire
                )
                hrr_msg = bytearray(_pack_handshake(HS_SERVER_HELLO, hrr_body))
                if ech_ok and inner_rand is not None and inner_ch1_msg is not None:
                    # Last 8 bytes of hrr_msg are the 0xFE0D payload
                    ech_offset = len(hrr_msg) - 8
                    conf = compute_hrr_ech_accept_confirmation(
                        spec, inner_rand, inner_ch1_msg, bytes(hrr_msg), ech_offset
                    )
                    hrr_msg[ech_offset : ech_offset + 8] = conf

                msg_hash = (
                    bytes([HS_MESSAGE_HASH, 0x00, 0x00, spec.hash_len])
                    + hash_bytes(spec.hash_alg, bytes(transcript))
                )
                transcript = bytearray(msg_hash + bytes(hrr_msg))
                writer.write(_pack_plaintext_record(CONTENT_HANDSHAKE, bytes(hrr_msg), TLS_VERSION_1_2))
                await writer.drain()

                # Read CH2 (skipping optional client dummy CCS)
                while True:
                    rtype2, _h2, rec2 = await self._read_record(reader)
                    if rtype2 == CONTENT_CHANGE_CIPHER_SPEC:
                        continue
                    break
                ch2_body = rec2[4:]
                _or2, osid2, oexts2, ospans2 = _parse_ch_fields(ch2_body)
                assert osid2 == outer_sid
                if ech_ok:
                    ok2, opener, inner_ch2_msg, inner_rand2, _isni2, inner_exts2 = self._try_decrypt_ech(
                        ch2_body, oexts2, ospans2, osid2, opener
                    )
                    assert ok2 and inner_ch2_msg is not None and inner_exts2 is not None
                    assert inner_rand2 == inner_rand
                    transcript.extend(inner_ch2_msg)
                    active_exts = inner_exts2
                else:
                    transcript.extend(rec2)
                    active_exts = oexts2

            self.ech_accepted_history.append(ech_ok)

            # Pick key_share group
            client_shares = _extract_client_key_shares(active_exts[EXT_KEY_SHARE])
            group = self.cfg.hrr_illegal_reply_group or self.cfg.require_hrr_group or GROUP_X25519
            client_pub = client_shares.get(group) or next(iter(client_shares.values()))

            if group == GROUP_X25519:
                srv_sk: Any = x25519.X25519PrivateKey.generate()
                srv_pub = srv_sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                if len(client_pub) == 32:
                    shared_secret = srv_sk.exchange(x25519.X25519PublicKey.from_public_bytes(client_pub))
                else:
                    shared_secret = b"\x42" * 32
            else:
                srv_sk = ec.generate_private_key(ec.SECP256R1())
                srv_pub = srv_sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                peer_ec = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub)
                shared_secret = srv_sk.exchange(ec.ECDH(), peer_ec)

            sh_ext_pairs: List[Tuple[int, bytes]] = [
                (EXT_SUPPORTED_VERSIONS, struct.pack("!H", TLS_VERSION_1_3)),
                (EXT_KEY_SHARE, struct.pack("!HH", group, len(srv_pub)) + srv_pub),
            ]
            sh_ext_pairs.extend(self.cfg.extra_sh_extensions)
            sh_exts = b"".join(_pack_ext(t, v) for t, v in sh_ext_pairs)
            srv_rand = bytearray(os.urandom(32))
            sh_body = (
                struct.pack("!H", TLS_VERSION_1_2)
                + bytes(srv_rand)
                + bytes([len(outer_sid)])
                + outer_sid
                + struct.pack("!HB", self.cfg.cipher_suite, 0)
                + struct.pack("!H", len(sh_exts))
                + sh_exts
            )
            sh_msg = bytearray(_pack_handshake(HS_SERVER_HELLO, sh_body))
            if ech_ok and inner_rand is not None:
                conf = compute_ech_accept_confirmation(
                    spec, inner_rand, bytes(transcript), bytes(sh_msg)
                )
                sh_msg[30:38] = conf

            transcript.extend(sh_msg)
            th_sh = hash_bytes(spec.hash_alg, bytes(transcript))
            _, client_hs_sec, server_hs_sec, master_sec = compute_handshake_secrets(
                spec, shared_secret, th_sh
            )
            srv_hs_cipher = TlsRecordCipher(spec, server_hs_sec)
            cli_hs_cipher = TlsRecordCipher(spec, client_hs_sec)

            # EncryptedExtensions
            ee_ext_list: List[Tuple[int, bytes]] = []
            if not ech_ok and self.cfg.retry_configs_on_reject is not None:
                ee_ext_list.append((EXT_ENCRYPTED_CLIENT_HELLO, self.cfg.retry_configs_on_reject))
            if self.cfg.ee_alpn is not None:
                pb = self.cfg.ee_alpn.encode("ascii")
                entry = bytes([len(pb)]) + pb
                ee_ext_list.append((EXT_ALPN, struct.pack("!H", len(entry)) + entry))
            ee_wire = b"".join(_pack_ext(t, v) for t, v in ee_ext_list)
            ee_msg = _pack_handshake(HS_ENCRYPTED_EXTENSIONS, struct.pack("!H", len(ee_wire)) + ee_wire)
            transcript.extend(ee_msg)

            # Certificate
            cert_to_use = self.cfg.inner_cert if ech_ok else self.cfg.outer_cert
            key_to_use = self.cfg.inner_key if ech_ok else self.cfg.outer_key
            scheme_to_use = self.cfg.inner_sig_scheme if ech_ok else self.cfg.outer_sig_scheme
            cert_msg = _pack_handshake(HS_CERTIFICATE, _encode_cert_message([cert_to_use]))
            transcript.extend(cert_msg)

            # CertificateVerify
            th_cv = hash_bytes(spec.hash_alg, bytes(transcript))
            cv_body = bytearray(_sign_cert_verify(key_to_use, scheme_to_use, th_cv))
            if self.cfg.tamper_cert_verify:
                cv_body[-1] ^= 0xFF
            cv_msg = _pack_handshake(HS_CERTIFICATE_VERIFY, bytes(cv_body))
            transcript.extend(cv_msg)

            # Server Finished
            th_sf = hash_bytes(spec.hash_alg, bytes(transcript))
            sf_mac = bytearray(derive_finished_verify_data(spec.hash_alg, server_hs_sec, th_sf))
            if self.cfg.tamper_server_finished:
                sf_mac[0] ^= 0xFF
            sf_msg = _pack_handshake(HS_FINISHED, bytes(sf_mac))
            transcript.extend(sf_msg)

            flight = ee_msg + cert_msg + cv_msg + sf_msg
            if self.cfg.coalesce_plaintext_flight_with_sh:
                # Attack: coalesce ServerHello + entire unencrypted server flight in ONE plaintext 0x16 record!
                writer.write(_pack_plaintext_record(CONTENT_HANDSHAKE, bytes(sh_msg) + flight, TLS_VERSION_1_2))
                await writer.drain()
            else:
                # Send ServerHello (+ optional middlebox CCS)
                writer.write(_pack_plaintext_record(CONTENT_HANDSHAKE, bytes(sh_msg), TLS_VERSION_1_2))
                if self.cfg.send_ccs:
                    writer.write(_pack_plaintext_record(CONTENT_CHANGE_CIPHER_SPEC, b"\x01", TLS_VERSION_1_2))
                if self.cfg.fragment_server_flight:
                    # Split across multiple small TLS records (splitting mid-handshake-message!)
                    step = 37
                    for off in range(0, len(flight), step):
                        writer.write(srv_hs_cipher.encrypt_record(CONTENT_HANDSHAKE, flight[off : off + step]))
                else:
                    writer.write(srv_hs_cipher.encrypt_record(CONTENT_HANDSHAKE, flight))
                await writer.drain()

            th_after_sf = hash_bytes(spec.hash_alg, bytes(transcript))
            cli_app_sec, srv_app_sec = compute_app_secrets(spec, master_sec, th_after_sf)
            srv_app_cipher = TlsRecordCipher(spec, srv_app_sec)
            cli_app_cipher = TlsRecordCipher(spec, cli_app_sec)

            # Read client Finished or Alert (e.g. ech_required on rejection!)
            while True:
                try:
                    rtype_c, hdr_c, body_c = await self._read_record(reader)
                except asyncio.IncompleteReadError:
                    return
                if rtype_c == CONTENT_CHANGE_CIPHER_SPEC:
                    continue
                if rtype_c == CONTENT_ALERT and len(body_c) == 2:
                    self.observed_alerts.append((body_c[0], body_c[1]))
                    return
                if rtype_c == CONTENT_APPLICATION_DATA:
                    itype, content = cli_hs_cipher.decrypt_record(hdr_c, body_c)
                    if itype == CONTENT_ALERT and len(content) == 2:
                        self.observed_alerts.append((content[0], content[1]))
                        return
                    if itype == CONTENT_HANDSHAKE and content[0] == HS_FINISHED:
                        break

            # Optional post-handshake NewSessionTicket and KeyUpdate
            if self.cfg.send_new_session_ticket:
                nst = _pack_handshake(HS_NEW_SESSION_TICKET, b"\x00\x00\x0e\x10" + b"\x00" * 12)
                writer.write(srv_app_cipher.encrypt_record(CONTENT_HANDSHAKE, nst))
            if self.cfg.send_key_update is not None:
                ku = _pack_handshake(HS_KEY_UPDATE, bytes([self.cfg.send_key_update]))
                writer.write(srv_app_cipher.encrypt_record(CONTENT_HANDSHAKE, ku))
                srv_app_cipher.update_keys()
            await writer.drain()

            # Echo application data until EOF / close_notify
            while True:
                try:
                    rtype_a, hdr_a, body_a = await self._read_record(reader)
                except asyncio.IncompleteReadError:
                    return
                if rtype_a != CONTENT_APPLICATION_DATA:
                    return
                itype, content = cli_app_cipher.decrypt_record(hdr_a, body_a)
                if itype == CONTENT_HANDSHAKE and content and content[0] == HS_KEY_UPDATE:
                    cli_app_cipher.update_keys()
                    continue
                if itype == CONTENT_ALERT:
                    if len(content) == 2:
                        self.observed_alerts.append((content[0], content[1]))
                    return
                if itype == CONTENT_APPLICATION_DATA:
                    self.observed_app_bytes.append(content)
                    if self.cfg.http_401_json is not None:
                        body_bytes = self.cfg.http_401_json.encode("utf-8")
                        resp = (
                            b"HTTP/1.1 401 Unauthorized\r\n"
                            b"Content-Type: application/json\r\n"
                            + f"Content-Length: {len(body_bytes)}\r\n".encode("ascii")
                            + b"Connection: close\r\n\r\n"
                            + body_bytes
                        )
                        writer.write(srv_app_cipher.encrypt_record(CONTENT_APPLICATION_DATA, resp))
                        await writer.drain()
                        return
                    reply = content
                    if self.cfg.extra_padding_bytes > 0:
                        # Manually craft padded TLSInnerPlaintext (<= 16384B content + 1B type + pad)
                        # to verify trailing zero-padding stripping on the client!
                        max_chunk = MAX_PLAINTEXT_RECORD_LEN - self.cfg.extra_padding_bytes
                        for off in range(0, len(reply), max_chunk):
                            piece = reply[off : off + max_chunk]
                            inner_pt = (
                                piece
                                + bytes([CONTENT_APPLICATION_DATA])
                                + (b"\x00" * self.cfg.extra_padding_bytes)
                            )
                            ct_len = len(inner_pt) + 16
                            rhdr = struct.pack("!BHH", CONTENT_APPLICATION_DATA, TLS_VERSION_1_2, ct_len)
                            nonce = srv_app_cipher._nonce()
                            ct = srv_app_cipher._aead.encrypt(nonce, inner_pt, rhdr)
                            srv_app_cipher.seq += 1
                            writer.write(rhdr + ct)
                    else:
                        for off in range(0, len(reply), MAX_PLAINTEXT_RECORD_LEN):
                            writer.write(
                                srv_app_cipher.encrypt_record(
                                    CONTENT_APPLICATION_DATA,
                                    reply[off : off + MAX_PLAINTEXT_RECORD_LEN],
                                )
                            )
                    await writer.drain()
        except Exception:
            return
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def _dial_loopback(port: int) -> Tuple[socket.socket, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    loop = asyncio.get_running_loop()
    await loop.sock_connect(sock, ("127.0.0.1", port))
    return sock, "127.0.0.1"


# ---------------------------------------------------------------------------
# Unit Tests: Padding, AAD, Confirmation, Record Layer, X.509 PolicyBuilder
# ---------------------------------------------------------------------------


class TestTls13EchPrimitives(unittest.TestCase):
    def test_rfc9849_padding_lengths_and_alignment(self) -> None:
        # With SNI shorter than L
        padded = pad_encoded_client_hello_inner(b"x" * 100, b"a.com", 64)
        self.assertEqual(len(padded) % 32, 0)
        self.assertGreaterEqual(len(padded), 100 + (64 - 5))
        self.assertTrue(padded[100:] == b"\x00" * (len(padded) - 100))

        # With SNI longer than L -> name_pad == 0
        padded2 = pad_encoded_client_hello_inner(b"x" * 100, b"a" * 80, 32)
        self.assertEqual(len(padded2), 128)  # next multiple of 32 >= 100

        # With maximum_name_length == 0 -> L = 255
        padded3 = pad_encoded_client_hello_inner(b"x" * 10, b"host", 0)
        self.assertEqual(len(padded3) % 32, 0)
        self.assertGreaterEqual(len(padded3), 10 + 251)

        # Without SNI (IP literal) -> name_pad = L + 9
        padded4 = pad_encoded_client_hello_inner(b"x" * 10, None, 64)
        self.assertEqual(len(padded4) % 32, 0)
        self.assertGreaterEqual(len(padded4), 10 + 64 + 9)

    def test_client_hello_outer_aad_and_hpke_roundtrip(self) -> None:
        sk_r, raw_cfg, cfg_list = _make_ech_keypair()
        selected = select_ech_config(cfg_list)
        assert selected is not None
        enc, sealer = setup_base_s(
            selected.kem_id,
            selected.kdf_id,
            selected.aead_id,
            selected.public_key,
            selected.hpke_info,
        )
        sid = os.urandom(32)
        inner_rand = os.urandom(32)
        outer_rand = os.urandom(32)
        ks_pub = os.urandom(32)

        inner_msg, outer_msg, outer_aad = build_ech_client_hello_pair(
            selected=selected,
            hpke_sealer=sealer,
            enc_for_outer=enc,
            real_host="secret.neruton.test",
            inner_random=inner_rand,
            outer_random=outer_rand,
            session_id=sid,
            inner_key_share=(GROUP_X25519, ks_pub),
            outer_key_share=(GROUP_X25519, os.urandom(32)),
        )
        # Outer ClientHello must NOT contain real_host in plaintext, MUST contain public_name!
        self.assertNotIn(b"secret.neruton.test", outer_msg)
        self.assertIn(b"public-outer.example.test", outer_msg)
        # outer_aad has NO 4-byte Handshake header (length == len(outer_msg) - 4)
        self.assertEqual(len(outer_aad), len(outer_msg) - 4)
        self.assertEqual(outer_aad[:2], b"\x03\x03")

        # Receiver HPKE open with outer_aad recovers EncodedClientHelloInner with empty session_id
        _r, _s, oexts, _ = _parse_ch_fields(outer_msg[4:])
        ech_ext = oexts[EXT_ENCRYPTED_CLIENT_HELLO]
        (enc_len,) = struct.unpack_from("!H", ech_ext, 6)
        enc_wire = ech_ext[8 : 8 + enc_len]
        self.assertEqual(enc_wire, enc)
        (plen,) = struct.unpack_from("!H", ech_ext, 8 + enc_len)
        payload = ech_ext[10 + enc_len : 10 + enc_len + plen]

        opener = setup_base_r(
            selected.kem_id,
            selected.kdf_id,
            selected.aead_id,
            enc_wire,
            sk_r,
            selected.hpke_info,
        )
        recovered = opener.open(outer_aad, payload)
        self.assertEqual(len(recovered) % 32, 0)
        # session_id inside EncodedClientHelloInner MUST be empty (0x00)
        self.assertEqual(recovered[34], 0)
        self.assertIn(b"secret.neruton.test", recovered)
        # logical inner_msg has the 32-byte session_id matching outer!
        self.assertEqual(inner_msg[38], 32)
        self.assertEqual(inner_msg[39:71], sid)

    def test_record_cipher_padding_stripping_key_update_and_errors(self) -> None:
        for suite_id in (
            TLS_AES_128_GCM_SHA256,
            TLS_AES_256_GCM_SHA384,
            TLS_CHACHA20_POLY1305_SHA256,
        ):
            spec = CIPHER_SUITES[suite_id]
            secret = os.urandom(spec.hash_len)
            tx = TlsRecordCipher(spec, secret)
            rx = TlsRecordCipher(spec, secret)

            rec = tx.encrypt_record(CONTENT_APPLICATION_DATA, b"hello-tls13")
            itype, pt = rx.decrypt_record(rec[:5], rec[5:])
            self.assertEqual((itype, pt), (CONTENT_APPLICATION_DATA, b"hello-tls13"))

            # Tampered ciphertext rejected
            bad = bytearray(rec)
            bad[-1] ^= 0x01
            with self.assertRaises(TlsError):
                rx.decrypt_record(bytes(bad[:5]), bytes(bad[5:]))

            # All-zero inner plaintext rejected
            nonce = tx._nonce()
            inner_zeros = b"\x00" * 16
            hdr = struct.pack("!BHH", CONTENT_APPLICATION_DATA, TLS_VERSION_1_2, len(inner_zeros) + 16)
            ct = tx._aead.encrypt(nonce, inner_zeros, hdr)
            tx.seq += 1
            with self.assertRaises(TlsError):
                rx.decrypt_record(hdr, ct)

            # KeyUpdate rotates keys and resets seq to 0
            tx.update_keys()
            rx.update_keys()
            self.assertEqual(tx.seq, 0)
            self.assertEqual(rx.seq, 0)
            rec2 = tx.encrypt_record(CONTENT_APPLICATION_DATA, b"post-key-update")
            itype2, pt2 = rx.decrypt_record(rec2[:5], rec2[5:])
            self.assertEqual((itype2, pt2), (CONTENT_APPLICATION_DATA, b"post-key-update"))

    def test_strict_x509_policy_builder_validation(self) -> None:
        ca_key, ca_cert = _build_ca("Valid Root CA", is_ca=True)
        store = Store([ca_cert])

        # 1. Valid DNS + wildcard + IP SAN
        _, leaf_ok, _ = _build_leaf(
            ca_key,
            ca_cert,
            cn="real.example.test",
            san_dns=("real.example.test", "*.sub.example.test"),
            san_ips=("127.0.0.1",),
        )
        verify_server_certificate_chain([leaf_ok], "real.example.test", store=store)
        verify_server_certificate_chain([leaf_ok], "app.sub.example.test", store=store)
        verify_server_certificate_chain([leaf_ok], "127.0.0.1", store=store)

        # 2. Wrong hostname -> rejected
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_server_certificate_chain([leaf_ok], "evil.example.test", store=store)

        # 3. Expired leaf -> rejected
        _, leaf_expired, _ = _build_leaf(
            ca_key,
            ca_cert,
            cn="expired.example.test",
            san_dns=("expired.example.test",),
            not_before_offset_hours=-48,
            not_after_offset_hours=-1,
        )
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_server_certificate_chain([leaf_expired], "expired.example.test", store=store)

        # 4. Non-CA issuer signing leaf -> rejected!
        fake_ca_key, fake_ca_cert = _build_ca("Non-CA Issuer", is_ca=False)
        _, leaf_from_non_ca, _ = _build_leaf(
            fake_ca_key,
            fake_ca_cert,
            cn="nonca.example.test",
            san_dns=("nonca.example.test",),
        )
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_server_certificate_chain(
                [leaf_from_non_ca], "nonca.example.test", store=Store([fake_ca_cert])
            )

        # 5. Untrusted CA -> rejected
        other_ca_key, other_ca_cert = _build_ca("Untrusted Root CA", is_ca=True)
        _, leaf_untrusted, _ = _build_leaf(
            other_ca_key,
            other_ca_cert,
            cn="real.example.test",
            san_dns=("real.example.test",),
        )
        with self.assertRaises(ssl.SSLCertVerificationError):
            verify_server_certificate_chain([leaf_untrusted], "real.example.test", store=store)


# ---------------------------------------------------------------------------
# Mock TLS 1.3 ECH Server End-to-End Handshake & Interop Tests
# ---------------------------------------------------------------------------


class _CollectProtocol(asyncio.Protocol):
    def __init__(self, expected_len: int) -> None:
        self.expected_len = expected_len
        self.received = bytearray()
        self.done = asyncio.Event()
        self.eof = False
        self.lost_exc: Optional[Exception] = None

    def data_received(self, data: bytes) -> None:
        self.received.extend(data)
        if len(self.received) >= self.expected_len:
            self.done.set()

    def eof_received(self) -> Optional[bool]:
        self.eof = True
        self.done.set()
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.lost_exc = exc
        self.done.set()


class TestMockTls13EchServer(unittest.IsolatedAsyncioTestCase):
    async def test_ech_accepted_suites_sig_algs_chunking_padding_nst_and_key_update(self) -> None:
        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        outer_key, outer_cert, outer_sig = _build_leaf(
            ca_key, ca_cert, cn="public-outer.example.test", san_dns=("public-outer.example.test",)
        )

        # Exercise all 3 TLS 1.3 cipher suites, both HPKE KEMs (X25519 + P-256),
        # and all 4 CertificateVerify key types (ECDSA-P256, ECDSA-P384, RSA-PSS, Ed25519)!
        cases = [
            (KEM_DHKEM_X25519_HKDF_SHA256, AEAD_AES_128_GCM, TLS_AES_128_GCM_SHA256, "ecdsa_p256", True, True, 1, 27),
            (KEM_DHKEM_P256_HKDF_SHA256, AEAD_AES_256_GCM, TLS_AES_256_GCM_SHA384, "rsa", True, True, 0, 0),
            (KEM_DHKEM_X25519_HKDF_SHA256, AEAD_CHACHA20_POLY1305, TLS_CHACHA20_POLY1305_SHA256, "ecdsa_p384", False, True, None, 13),
            (KEM_DHKEM_X25519_HKDF_SHA256, AEAD_AES_128_GCM, TLS_AES_128_GCM_SHA256, "ed25519", True, False, None, 0),
        ]

        for kem_id, hpke_aead, tls_cs, key_kind, frag, nst, ku, extra_pad in cases:
            inner_key, inner_cert, inner_sig = _build_leaf(
                ca_key,
                ca_cert,
                cn="secret.neruton.test",
                san_dns=("secret.neruton.test",),
                key_kind=key_kind,
            )
            sk_r, raw_cfg, cfg_list = _make_ech_keypair(kem_id, aead_id=hpke_aead)
            srv = _MockTls13EchServer(
                _MockEchServerConfig(
                    ech_sk_bytes=sk_r,
                    ech_raw_config=raw_cfg,
                    ech_kem_id=kem_id,
                    ech_config_id=42,
                    inner_key=inner_key,
                    inner_cert=inner_cert,
                    inner_sig_scheme=inner_sig,
                    outer_key=outer_key,
                    outer_cert=outer_cert,
                    outer_sig_scheme=outer_sig,
                    cipher_suite=tls_cs,
                    send_ccs=True,
                    fragment_server_flight=frag,
                    send_new_session_ticket=nst,
                    send_key_update=ku,
                    extra_padding_bytes=extra_pad,
                )
            )
            await srv.start()
            try:
                # Write payload > 16384 bytes on first case to verify outbound record chunking!
                payload = (b"A" * 20000) if key_kind == "ecdsa_p256" else f"hi-{key_kind}".encode()
                proto = _CollectProtocol(len(payload))
                res = await connect_tls13_ech(
                    sock_factory=lambda p=srv.port: _dial_loopback(p),
                    real_host="secret.neruton.test",
                    ech_config_list=cfg_list,
                    protocol=proto,
                    base_ssl_context=ca_ctx,
                    call_connection_made=True,
                )
                try:
                    self.assertEqual(res.ech_status, "accepted")
                    self.assertEqual(res.outer_sni, "public-outer.example.test")
                    self.assertFalse(res.retried)
                    self.assertEqual(srv.observed_outer_snis, ["public-outer.example.test"])
                    self.assertEqual(srv.observed_inner_snis, ["secret.neruton.test"])

                    res.transport.write(payload)
                    await asyncio.wait_for(proto.done.wait(), timeout=3.0)
                    self.assertEqual(bytes(proto.received), payload)
                finally:
                    res.transport.close()
            finally:
                await srv.stop()

    async def test_hrr_with_secp256r1_and_cookie_accepts_ech(self) -> None:
        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        inner_key, inner_cert, inner_sig = _build_leaf(
            ca_key, ca_cert, cn="hrr.neruton.test", san_dns=("hrr.neruton.test",)
        )
        outer_key, outer_cert, outer_sig = _build_leaf(
            ca_key, ca_cert, cn="public-outer.example.test", san_dns=("public-outer.example.test",)
        )
        sk_r, raw_cfg, cfg_list = _make_ech_keypair()

        srv = _MockTls13EchServer(
            _MockEchServerConfig(
                ech_sk_bytes=sk_r,
                ech_raw_config=raw_cfg,
                ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                ech_config_id=42,
                inner_key=inner_key,
                inner_cert=inner_cert,
                inner_sig_scheme=inner_sig,
                outer_key=outer_key,
                outer_cert=outer_cert,
                outer_sig_scheme=outer_sig,
                require_hrr_group=GROUP_SECP256R1,
                require_hrr_cookie=b"neruton-hrr-cookie-123",
                cipher_suite=TLS_AES_256_GCM_SHA384,
            )
        )
        await srv.start()
        try:
            proto = _CollectProtocol(len(b"after-hrr"))
            res = await connect_tls13_ech(
                sock_factory=lambda: _dial_loopback(srv.port),
                real_host="hrr.neruton.test",
                ech_config_list=cfg_list,
                protocol=proto,
                base_ssl_context=ca_ctx,
                call_connection_made=True,
            )
            try:
                self.assertEqual(res.ech_status, "accepted")
                self.assertEqual(srv.ech_accepted_history, [True])
                res.transport.write(b"after-hrr")
                await asyncio.wait_for(proto.done.wait(), timeout=3.0)
                self.assertEqual(bytes(proto.received), b"after-hrr")
            finally:
                res.transport.close()
        finally:
            await srv.stop()

    async def test_ech_rejection_authenticates_outer_sends_ech_required_and_retries_once(self) -> None:
        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        inner_key, inner_cert, inner_sig = _build_leaf(
            ca_key, ca_cert, cn="real.neruton.test", san_dns=("real.neruton.test",)
        )
        outer_key, outer_cert, outer_sig = _build_leaf(
            ca_key, ca_cert, cn="public-outer.example.test", san_dns=("public-outer.example.test",)
        )
        # Fresh server ECH keypair (config_id=99), client starts with stale keypair (config_id=1)!
        fresh_sk, fresh_raw, fresh_list = _make_ech_keypair(config_id=99)
        _, _, stale_list = _make_ech_keypair(config_id=1)

        srv = _MockTls13EchServer(
            _MockEchServerConfig(
                ech_sk_bytes=fresh_sk,
                ech_raw_config=fresh_raw,
                ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                ech_config_id=99,
                inner_key=inner_key,
                inner_cert=inner_cert,
                inner_sig_scheme=inner_sig,
                outer_key=outer_key,
                outer_cert=outer_cert,
                outer_sig_scheme=outer_sig,
                retry_configs_on_reject=fresh_list,
            )
        )
        await srv.start()
        try:
            warnings_seen: List[str] = []
            proto = _CollectProtocol(len(b"secret-token-safe"))
            res = await connect_tls13_ech(
                sock_factory=lambda: _dial_loopback(srv.port),
                real_host="real.neruton.test",
                ech_config_list=stale_list,
                protocol=proto,
                base_ssl_context=ca_ctx,
                call_connection_made=True,
                on_warn=warnings_seen.append,
            )
            try:
                self.assertEqual(res.ech_status, "accepted")
                self.assertTrue(res.retried)
                self.assertEqual(res.outer_sni, "public-outer.example.test")
                self.assertEqual(srv.connections, 2)
                self.assertEqual(srv.ech_accepted_history, [False, True])
                # Attempt 1 MUST have sent fatal ech_required (121) and ZERO app data!
                self.assertIn((ALERT_LEVEL_FATAL, ALERT_ECH_REQUIRED), srv.observed_alerts)
                self.assertEqual(srv.observed_app_bytes, [])
                self.assertEqual(len(warnings_seen), 1)
                self.assertIn("retry_configs", warnings_seen[0])

                # Now app data flows on the retried, ECH-accepted connection!
                res.transport.write(b"secret-token-safe")
                await asyncio.wait_for(proto.done.wait(), timeout=3.0)
                self.assertEqual(bytes(proto.received), b"secret-token-safe")
            finally:
                res.transport.close()
        finally:
            await srv.stop()

    async def test_ech_rejection_with_wrong_outer_cert_never_trusts_retry_configs(self) -> None:
        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        inner_key, inner_cert, inner_sig = _build_leaf(
            ca_key, ca_cert, cn="real.neruton.test", san_dns=("real.neruton.test",)
        )
        # Outer cert is for WRONG hostname (not public-outer.example.test)!
        wrong_outer_key, wrong_outer_cert, wrong_outer_sig = _build_leaf(
            ca_key, ca_cert, cn="imposter.example.test", san_dns=("imposter.example.test",)
        )
        fresh_sk, fresh_raw, fresh_list = _make_ech_keypair(config_id=99)
        _, _, stale_list = _make_ech_keypair(config_id=1)

        srv = _MockTls13EchServer(
            _MockEchServerConfig(
                ech_sk_bytes=fresh_sk,
                ech_raw_config=fresh_raw,
                ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                ech_config_id=99,
                inner_key=inner_key,
                inner_cert=inner_cert,
                inner_sig_scheme=inner_sig,
                outer_key=wrong_outer_key,
                outer_cert=wrong_outer_cert,
                outer_sig_scheme=wrong_outer_sig,
                retry_configs_on_reject=fresh_list,
            )
        )
        await srv.start()
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                await connect_tls13_ech(
                    sock_factory=lambda: _dial_loopback(srv.port),
                    real_host="real.neruton.test",
                    ech_config_list=stale_list,
                    base_ssl_context=ca_ctx,
                )
            # Must NOT have retried with unauthenticated retry_configs!
            self.assertEqual(srv.connections, 1)
            self.assertEqual(srv.observed_app_bytes, [])
        finally:
            await srv.stop()

    async def test_tampered_cert_verify_and_tampered_finished_fail_cleanly(self) -> None:
        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        inner_key, inner_cert, inner_sig = _build_leaf(
            ca_key, ca_cert, cn="real.neruton.test", san_dns=("real.neruton.test",)
        )
        outer_key, outer_cert, outer_sig = _build_leaf(
            ca_key, ca_cert, cn="public-outer.example.test", san_dns=("public-outer.example.test",)
        )
        sk_r, raw_cfg, cfg_list = _make_ech_keypair()

        for tamper_cv, tamper_sf in ((True, False), (False, True)):
            srv = _MockTls13EchServer(
                _MockEchServerConfig(
                    ech_sk_bytes=sk_r,
                    ech_raw_config=raw_cfg,
                    ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                    ech_config_id=42,
                    inner_key=inner_key,
                    inner_cert=inner_cert,
                    inner_sig_scheme=inner_sig,
                    outer_key=outer_key,
                    outer_cert=outer_cert,
                    outer_sig_scheme=outer_sig,
                    tamper_cert_verify=tamper_cv,
                    tamper_server_finished=tamper_sf,
                )
            )
            await srv.start()
            try:
                with self.assertRaises(TlsError):
                    await connect_tls13_ech(
                        sock_factory=lambda p=srv.port: _dial_loopback(p),
                        real_host="real.neruton.test",
                        ech_config_list=cfg_list,
                        base_ssl_context=ca_ctx,
                    )
                self.assertEqual(srv.observed_app_bytes, [])
            finally:
                await srv.stop()

    async def test_rejection_without_retry_configs_fails_and_cancel_leaks_no_fds(self) -> None:
        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        inner_key, inner_cert, inner_sig = _build_leaf(
            ca_key, ca_cert, cn="real.neruton.test", san_dns=("real.neruton.test",)
        )
        outer_key, outer_cert, outer_sig = _build_leaf(
            ca_key, ca_cert, cn="public-outer.example.test", san_dns=("public-outer.example.test",)
        )
        sk_r, raw_cfg, cfg_list = _make_ech_keypair()

        srv = _MockTls13EchServer(
            _MockEchServerConfig(
                ech_sk_bytes=sk_r,
                ech_raw_config=raw_cfg,
                ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                ech_config_id=42,
                inner_key=inner_key,
                inner_cert=inner_cert,
                inner_sig_scheme=inner_sig,
                outer_key=outer_key,
                outer_cert=outer_cert,
                outer_sig_scheme=outer_sig,
                force_reject_ech=True,
                retry_configs_on_reject=None,
            )
        )
        await srv.start()
        try:
            with self.assertRaises(EchRejectedError):
                await connect_tls13_ech(
                    sock_factory=lambda: _dial_loopback(srv.port),
                    real_host="real.neruton.test",
                    ech_config_list=cfg_list,
                    base_ssl_context=ca_ctx,
                )
            self.assertEqual(srv.observed_app_bytes, [])
        finally:
            await srv.stop()

        # Cancellation mid-handshake leaks zero sockets & zero tasks!
        eof_seen = asyncio.Event()

        async def _stall(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
            try:
                while await r.read(1024):
                    pass
                eof_seen.set()
            finally:
                w.close()
                with contextlib.suppress(Exception):
                    await w.wait_closed()

        stall_srv = await asyncio.start_server(_stall, "127.0.0.1", 0)
        stall_port = int(stall_srv.sockets[0].getsockname()[1])
        try:
            tasks_before = len(asyncio.all_tasks())
            opened_socks: List[socket.socket] = []

            async def _tracked_dial() -> Tuple[socket.socket, str]:
                s, ip = await _dial_loopback(stall_port)
                opened_socks.append(s)
                return s, ip

            task = asyncio.create_task(
                connect_tls13_ech(
                    sock_factory=_tracked_dial,
                    real_host="stall.neruton.test",
                    ech_config_list=cfg_list,
                    no_tls_verify=True,
                    handshake_timeout=10.0,
                )
            )
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(eof_seen.wait(), timeout=1.0)
            await asyncio.sleep(0.03)
            self.assertEqual(len(opened_socks), 1)
            self.assertEqual(opened_socks[0].fileno(), -1)
            self.assertEqual(len(asyncio.all_tasks()), tasks_before)
        finally:
            stall_srv.close()
            await stall_srv.wait_closed()

    async def test_open_websocket_ech_integration_401_retry_and_auto_fallback(self) -> None:
        from test_stealth import _MockDohServer

        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        inner_key, inner_cert, inner_sig = _build_leaf(
            ca_key, ca_cert, cn="real.neruton.test", san_dns=("real.neruton.test",)
        )
        outer_key, outer_cert, outer_sig = _build_leaf(
            ca_key, ca_cert, cn="public-outer.example.test", san_dns=("public-outer.example.test",)
        )
        fresh_sk, fresh_raw, fresh_list = _make_ech_keypair(config_id=77)
        _, _, stale_list = _make_ech_keypair(config_id=1)

        # 1. Mock DoH returns stale ECHConfigList; mock ECH server rejects -> retry_configs -> accepts -> HTTP 401 JSON!
        srv = _MockTls13EchServer(
            _MockEchServerConfig(
                ech_sk_bytes=fresh_sk,
                ech_raw_config=fresh_raw,
                ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                ech_config_id=77,
                inner_key=inner_key,
                inner_cert=inner_cert,
                inner_sig_scheme=inner_sig,
                outer_key=outer_key,
                outer_cert=outer_cert,
                outer_sig_scheme=outer_sig,
                retry_configs_on_reject=fresh_list,
                http_401_json='{"error":"invalid token"}',
            )
        )
        doh_srv = _MockDohServer(ipv4=("127.0.0.1",), ech_bytes=stale_list)
        await srv.start()
        await doh_srv.start()
        try:
            with self.assertRaises(AuthError) as cm:
                await _open_websocket(
                    f"wss://real.neruton.test:{srv.port}/_neruton/tunnel",
                    token="ntk_test_token",
                    no_tls_verify=False,
                    doh_config=DohConfig(mode="strict", endpoints=(doh_srv.url,), custom=True),
                    sni_mode="ech",
                    base_ssl_context=ca_ctx,
                )
            self.assertEqual(cm.exception.status_code, 401)
            self.assertEqual(cm.exception.server_message, "invalid token")
            tinfo = cm.exception.transport_info
            self.assertIsNotNone(tinfo)
            assert isinstance(tinfo, TransportInfo)
            self.assertEqual(tinfo.ech_status, "accepted")
            self.assertEqual(tinfo.outer_sni, "public-outer.example.test")
            self.assertTrue(tinfo.ech_retried)
            self.assertIn("DoH + ECH (outer: public-outer.example.test, retried)", tinfo.summary())
            # Token was ONLY sent on the 2nd (ECH-accepted) connection, NEVER on the rejected attempt!
            self.assertEqual(srv.connections, 2)
            self.assertEqual(len(srv.observed_app_bytes), 1)
            self.assertIn(b"Bearer ntk_test_token", srv.observed_app_bytes[0])
        finally:
            await srv.stop()
            await doh_srv.stop()

        # 2. TransportInfo.summary() formatting check for non-retried ECH & fallback
        info_ok = TransportInfo(
            doh_mode="auto",
            doh_used=True,
            doh_endpoint="https://1.0.0.1/dns-query",
            doh_fallback=False,
            resolved_ip="104.21.2.247",
            sni_mode="auto",
            effective_sni_mode="ech",
            wire_sni="cloudflare-ech.com",
            fragmented=False,
            fragment_count=0,
            tls_version="TLSv1.3",
            ech_available=True,
            ech_public_name="cloudflare-ech.com",
            ech_status="accepted",
            outer_sni="cloudflare-ech.com",
        )
        self.assertIn("DoH + ECH (outer: cloudflare-ech.com)", info_ok.summary())

        info_fb = TransportInfo(
            doh_mode="auto",
            doh_used=True,
            doh_endpoint="https://1.0.0.1/dns-query",
            doh_fallback=False,
            resolved_ip="104.21.2.247",
            sni_mode="auto",
            effective_sni_mode="fragment",
            wire_sni="neruton.moer.eu.org",
            fragmented=True,
            fragment_count=4,
            tls_version="TLSv1.3",
            ech_available=True,
            ech_public_name="cloudflare-ech.com",
            ech_status="fallback",
            outer_sni=None,
        )
        self.assertIn("ECH fallback", info_fb.summary())

        # 3. Real auto-mode fallback: DoH returns an incompatible/unusable ECHConfigList while
        # server is a plain TLS WebSocket server -> auto warns & falls back to ClientHello fragment
        # with ech_status == "fallback", while sni_mode="ech" fails fast with TunnelError!
        from websockets.asyncio.server import ServerConnection, serve

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cert_file = tmp_path / "srv.crt"
            key_file = tmp_path / "srv.key"
            cert_file.write_bytes(inner_cert.public_bytes(Encoding.PEM))
            key_file.write_bytes(
                inner_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
            )
            srv_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            srv_ssl.load_cert_chain(str(cert_file), str(key_file))

            async def _ws_ok(ws: ServerConnection) -> None:
                await ws.send("fallback-ok")
                await ws.close()

            ws_srv = await serve(_ws_ok, "127.0.0.1", 0, ssl=srv_ssl, compression=None)
            ws_port = int(ws_srv.sockets[0].getsockname()[1])
            # Incompatible ECHConfigList (unsupported version 0xFE0C only)
            incompat_cfg = encode_ech_config(
                config_id=5,
                kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                public_key=os.urandom(32),
                cipher_suites=[(KDF_HKDF_SHA256, AEAD_AES_128_GCM)],
                public_name="public-outer.example.test",
                version=0xFE0C,
            )
            incompat_list = encode_ech_config_list([incompat_cfg])
            doh_fb = _MockDohServer(ipv4=("127.0.0.1",), ech_bytes=incompat_list)
            await doh_fb.start()
            try:
                fb_warns: List[str] = []
                ws, info = await _open_websocket(
                    f"wss://real.neruton.test:{ws_port}/_neruton/tunnel",
                    token="ntk_fb",
                    no_tls_verify=False,
                    doh_config=DohConfig(mode="strict", endpoints=(doh_fb.url,), custom=True),
                    sni_mode="auto",
                    base_ssl_context=ca_ctx,
                    on_warn=fb_warns.append,
                )
                try:
                    self.assertEqual(await ws.recv(), "fallback-ok")
                    self.assertEqual(info.ech_status, "fallback")
                    self.assertEqual(info.effective_sni_mode, "fragment")
                    self.assertTrue(info.fragmented)
                    self.assertIsNone(info.outer_sni)
                    self.assertIn("ECH fallback", info.summary())
                    self.assertEqual(len(fb_warns), 1)
                finally:
                    await ws.close()

                # Strict sni_mode="ech" with same incompatible DoH ECH config MUST fail fast!
                with self.assertRaises(TunnelError):
                    await _open_websocket(
                        f"wss://real.neruton.test:{ws_port}/_neruton/tunnel",
                        token="ntk_never_sent",
                        no_tls_verify=False,
                        doh_config=DohConfig(mode="strict", endpoints=(doh_fb.url,), custom=True),
                        sni_mode="ech",
                        base_ssl_context=ca_ctx,
                    )
            finally:
                await doh_fb.stop()
                ws_srv.close()
                await ws_srv.wait_closed()

    async def test_security_regressions_1_to_4_and_6(self) -> None:
        from unittest import mock
        import neruton.client as client_mod
        from neruton.tls13_ech import Tls13EchTransport, _RawTcpProtocol

        # --- Regression #1 & #2b: Post-handshake transport record-layer hardening ---
        loop = asyncio.get_running_loop()
        spec = CIPHER_SUITES[TLS_AES_128_GCM_SHA256]

        class _FakeRawTransport(asyncio.Transport):
            def __init__(self) -> None:
                super().__init__()
                self.written: List[bytes] = []
                self.aborted = False
                self.closed = False

            def write(self, data: Any) -> None:
                self.written.append(bytes(data))

            def is_closing(self) -> bool:
                return self.aborted or self.closed

            def close(self) -> None:
                self.closed = True

            def abort(self) -> None:
                self.aborted = True

        def _make_transport_pair() -> Tuple[Tls13EchTransport, TlsRecordCipher, _FakeRawTransport, _CollectProtocol]:
            sec = os.urandom(32)
            raw_t = _FakeRawTransport()
            raw_p = _RawTcpProtocol(loop)
            raw_p.connection_made(raw_t)
            tls_t = Tls13EchTransport(
                loop=loop,
                raw_transport=raw_t,
                raw_protocol=raw_p,
                send_cipher=TlsRecordCipher(spec, sec),
                recv_cipher=TlsRecordCipher(spec, sec),
                cipher_spec=spec,
                outer_sni="public-outer.example.test",
                real_host="real.neruton.test",
            )
            proto = _CollectProtocol(1024)
            tls_t.set_protocol(proto)
            return tls_t, TlsRecordCipher(spec, sec), raw_t, proto

        # 1. Plaintext close_notify alert post-handshake MUST be rejected (no truncation!)
        t1, _srv1, raw1, proto1 = _make_transport_pair()
        t1._on_raw_data(bytes.fromhex("15030300020100"))
        self.assertTrue(raw1.aborted)
        self.assertFalse(proto1.eof)
        self.assertIsInstance(t1._pending_error, TlsError)

        # 2b-i. KeyUpdate coalesced with trailing handshake bytes MUST fail!
        t2, srv2, raw2, _ = _make_transport_pair()
        ku_plus_nst = _pack_handshake(HS_KEY_UPDATE, b"\x00") + _pack_handshake(HS_NEW_SESSION_TICKET, b"\x00" * 8)
        t2._on_raw_data(srv2.encrypt_record(CONTENT_HANDSHAKE, ku_plus_nst))
        self.assertTrue(raw2.aborted)
        self.assertIsInstance(t2._pending_error, TlsError)

        # 2b-ii. AppData interleaved inside fragmented post-handshake message MUST fail!
        t3, srv3, raw3, _ = _make_transport_pair()
        partial_nst = _pack_handshake(HS_NEW_SESSION_TICKET, b"\x00" * 20)[:6]
        t3._on_raw_data(
            srv3.encrypt_record(CONTENT_HANDSHAKE, partial_nst)
            + srv3.encrypt_record(CONTENT_APPLICATION_DATA, b"interleaved")
        )
        self.assertTrue(raw3.aborted)
        self.assertIsInstance(t3._pending_error, TlsError)

        # 2b-iii. Zero-length post-handshake Handshake fragment MUST fail!
        t4, srv4, raw4, _ = _make_transport_pair()
        t4._on_raw_data(srv4.encrypt_record(CONTENT_HANDSHAKE, b""))
        self.assertTrue(raw4.aborted)
        self.assertIsInstance(t4._pending_error, TlsError)

        # 2b-iv. Re-entrant close() inside protocol.data_received() stops draining later records!
        t5, srv5, raw5, _ = _make_transport_pair()
        delivered: List[bytes] = []

        class _CloseOnFirst(asyncio.Protocol):
            def data_received(self, data: bytes) -> None:
                delivered.append(data)
                t5.close()

        t5.set_protocol(_CloseOnFirst())
        t5._on_raw_data(
            srv5.encrypt_record(CONTENT_APPLICATION_DATA, b"first")
            + srv5.encrypt_record(CONTENT_APPLICATION_DATA, b"second")
        )
        self.assertEqual(delivered, [b"first"])
        self.assertTrue(raw5.closed)

        # --- Regressions #2a, #3, #4: Handshake-level attacks against mock server ---
        ca_key, ca_cert = _build_ca()
        ca_ctx = _ssl_context_for_ca(ca_cert)
        inner_key, inner_cert, inner_sig = _build_leaf(
            ca_key, ca_cert, cn="real.neruton.test", san_dns=("real.neruton.test",)
        )
        outer_key, outer_cert, outer_sig = _build_leaf(
            ca_key, ca_cert, cn="public-outer.example.test", san_dns=("public-outer.example.test",)
        )
        sk_r, raw_cfg, cfg_list = _make_ech_keypair()

        attack_configs = [
            # #2a: Coalesced plaintext flight after ServerHello in one plaintext 0x16 record
            (
                "coalesced-plaintext-flight",
                _MockEchServerConfig(
                    ech_sk_bytes=sk_r,
                    ech_raw_config=raw_cfg,
                    ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                    ech_config_id=42,
                    inner_key=inner_key,
                    inner_cert=inner_cert,
                    inner_sig_scheme=inner_sig,
                    outer_key=outer_key,
                    outer_cert=outer_cert,
                    outer_sig_scheme=outer_sig,
                    coalesce_plaintext_flight_with_sh=True,
                ),
                ("http/1.1",),
            ),
            # #3: HRR requests secp256r1, server illegally replies ServerHello(key_share=X25519)
            (
                "hrr-illegal-x25519-reply",
                _MockEchServerConfig(
                    ech_sk_bytes=sk_r,
                    ech_raw_config=raw_cfg,
                    ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                    ech_config_id=42,
                    inner_key=inner_key,
                    inner_cert=inner_cert,
                    inner_sig_scheme=inner_sig,
                    outer_key=outer_key,
                    outer_cert=outer_cert,
                    outer_sig_scheme=outer_sig,
                    require_hrr_group=GROUP_SECP256R1,
                    hrr_illegal_reply_group=GROUP_X25519,
                ),
                ("http/1.1",),
            ),
            # #4a: Non-HRR ServerHello illegally contains EXT_ENCRYPTED_CLIENT_HELLO (0xFE0D)
            (
                "sh-unsolicited-ech-ext",
                _MockEchServerConfig(
                    ech_sk_bytes=sk_r,
                    ech_raw_config=raw_cfg,
                    ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                    ech_config_id=42,
                    inner_key=inner_key,
                    inner_cert=inner_cert,
                    inner_sig_scheme=inner_sig,
                    outer_key=outer_key,
                    outer_cert=outer_cert,
                    outer_sig_scheme=outer_sig,
                    extra_sh_extensions=((EXT_ENCRYPTED_CLIENT_HELLO, b"\x00" * 8),),
                ),
                ("http/1.1",),
            ),
            # #4b: HRR contains unsolicited extension 0x1234
            (
                "hrr-unsolicited-ext",
                _MockEchServerConfig(
                    ech_sk_bytes=sk_r,
                    ech_raw_config=raw_cfg,
                    ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                    ech_config_id=42,
                    inner_key=inner_key,
                    inner_cert=inner_cert,
                    inner_sig_scheme=inner_sig,
                    outer_key=outer_key,
                    outer_cert=outer_cert,
                    outer_sig_scheme=outer_sig,
                    require_hrr_cookie=b"ck",
                    extra_hrr_extensions=((0x1234, b"\x01"),),
                ),
                ("http/1.1",),
            ),
            # #4c: EncryptedExtensions contains ALPN when client offered no ALPN
            (
                "ee-unsolicited-alpn",
                _MockEchServerConfig(
                    ech_sk_bytes=sk_r,
                    ech_raw_config=raw_cfg,
                    ech_kem_id=KEM_DHKEM_X25519_HKDF_SHA256,
                    ech_config_id=42,
                    inner_key=inner_key,
                    inner_cert=inner_cert,
                    inner_sig_scheme=inner_sig,
                    outer_key=outer_key,
                    outer_cert=outer_cert,
                    outer_sig_scheme=outer_sig,
                    ee_alpn="http/1.1",
                ),
                (),
            ),
        ]

        for label, scfg, alpn in attack_configs:
            srv = _MockTls13EchServer(scfg)
            await srv.start()
            try:
                with self.assertRaises(TlsError, msg=f"attack {label} MUST be rejected"):
                    await connect_tls13_ech(
                        sock_factory=lambda p=srv.port: _dial_loopback(p),
                        real_host="real.neruton.test",
                        ech_config_list=cfg_list,
                        base_ssl_context=ca_ctx,
                        alpn_protocols=alpn,
                    )
            finally:
                await srv.stop()

        # --- Regression #6: pyproject.toml floor & legacy websockets 12.x auto-mode fallback ---
        pyproject_text = (Path(__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("cryptography>=42.0.0", pyproject_text)
        self.assertIn("websockets>=13.0", pyproject_text)

        from test_stealth import _MockDohServer

        doh_legacy = _MockDohServer(ipv4=("127.0.0.1",), ech_bytes=cfg_list)
        await doh_legacy.start()
        try:
            legacy_warns: List[str] = []
            with mock.patch.object(client_mod, "_HAS_MODERN_WS", False):
                # Strict ech MUST still fail fast on websockets 12.x
                with self.assertRaises(TunnelError):
                    await _open_websocket(
                        "wss://real.neruton.test:443/_neruton/tunnel",
                        token="ntk_x",
                        no_tls_verify=False,
                        doh_config=DohConfig(mode="strict", endpoints=(doh_legacy.url,), custom=True),
                        sni_mode="ech",
                    )
                # Auto mode with DoH ECH falls back cleanly with warning instead of crashing with TunnelError!
                with mock.patch.object(client_mod.websockets, "connect", create=True, side_effect=OSError("dial-reached")) as m_conn:
                    try:
                        await _open_websocket(
                            "wss://real.neruton.test:1/_neruton/tunnel",
                            token="ntk_x",
                            no_tls_verify=False,
                            doh_config=DohConfig(mode="strict", endpoints=(doh_legacy.url,), custom=True),
                            sni_mode="auto",
                            on_warn=legacy_warns.append,
                        )
                    except Exception:
                        pass
                    self.assertTrue(any("websockets>=13.0" in w for w in legacy_warns))
        finally:
            await doh_legacy.stop()


if __name__ == "__main__":
    unittest.main()
