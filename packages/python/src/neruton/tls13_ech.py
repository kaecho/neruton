"""Pure-Python RFC 8446 TLS 1.3 + RFC 9849 ECH (Encrypted Client Hello) client & ``asyncio.Transport``.

Built directly on ``cryptography>=42.0.0`` (``AESGCM``, ``ChaCha20Poly1305``, ``X25519``,
``SECP256R1``, ``HKDFExpand``, ``HMAC``, ``PolicyBuilder`` + ``Store``) with zero C extensions
beyond ``cryptography`` and full compatibility with Python 3.9–3.14 (Linux, macOS, Windows
``ProactorEventLoop``, Colab, and Kaggle).
"""

from __future__ import annotations

import asyncio
import datetime
import hmac
import ipaddress
import logging
import os
import socket
import ssl
import struct
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Tuple, Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .doh import is_ip_literal, normalize_hostname
from .errors import TunnelConnectionError, TunnelError
from .hpke import (
    HpkeError,
    HpkeSealer,
    SelectedEchConfig,
    TAG_LEN as HPKE_TAG_LEN,
    select_ech_config,
    setup_base_s,
)

logger = logging.getLogger("neruton.tls13_ech")

# TLS Record ContentType (RFC 8446 §5.1)
CONTENT_CHANGE_CIPHER_SPEC = 0x14
CONTENT_ALERT = 0x15
CONTENT_HANDSHAKE = 0x16
CONTENT_APPLICATION_DATA = 0x17

# TLS Legacy / Protocol Versions
TLS_VERSION_1_0 = 0x0301
TLS_VERSION_1_2 = 0x0303
TLS_VERSION_1_3 = 0x0304

# TLS 1.3 HandshakeType (RFC 8446 §4)
HS_CLIENT_HELLO = 0x01
HS_SERVER_HELLO = 0x02
HS_NEW_SESSION_TICKET = 0x04
HS_ENCRYPTED_EXTENSIONS = 0x08
HS_CERTIFICATE = 0x0B
HS_CERTIFICATE_REQUEST = 0x0D
HS_CERTIFICATE_VERIFY = 0x0F
HS_FINISHED = 0x14
HS_KEY_UPDATE = 0x18
HS_MESSAGE_HASH = 0xFE

# TLS Extensions
EXT_SERVER_NAME = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_COOKIE = 0x002C
EXT_KEY_SHARE = 0x0033
EXT_ECH_OUTER_EXTENSIONS = 0xFD00
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D

# RFC 9849 ECH ClientHelloType
ECH_CLIENT_HELLO_OUTER = 0x00
ECH_CLIENT_HELLO_INNER = 0x01

# TLS 1.3 Cipher Suites (RFC 8446 §B.4)
TLS_AES_128_GCM_SHA256 = 0x1301
TLS_AES_256_GCM_SHA384 = 0x1302
TLS_CHACHA20_POLY1305_SHA256 = 0x1303

SUPPORTED_CIPHER_SUITES: Tuple[int, ...] = (
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
)

# NamedGroups (RFC 8446 §4.2.7)
GROUP_SECP256R1 = 0x0017
GROUP_X25519 = 0x001D

SUPPORTED_GROUPS: Tuple[int, ...] = (
    GROUP_X25519,
    GROUP_SECP256R1,
)

# SignatureSchemes (RFC 8446 §4.2.3)
SIG_ECDSA_SECP256R1_SHA256 = 0x0403
SIG_ECDSA_SECP384R1_SHA384 = 0x0503
SIG_RSA_PSS_RSAE_SHA256 = 0x0804
SIG_RSA_PSS_RSAE_SHA384 = 0x0805
SIG_RSA_PSS_RSAE_SHA512 = 0x0806
SIG_ED25519 = 0x0807
SIG_RSA_PSS_PSS_SHA256 = 0x0809
SIG_RSA_PSS_PSS_SHA384 = 0x080A
SIG_RSA_PSS_PSS_SHA512 = 0x080B

SUPPORTED_SIGNATURE_ALGORITHMS: Tuple[int, ...] = (
    SIG_ECDSA_SECP256R1_SHA256,
    SIG_ECDSA_SECP384R1_SHA384,
    SIG_ED25519,
    SIG_RSA_PSS_RSAE_SHA256,
    SIG_RSA_PSS_RSAE_SHA384,
    SIG_RSA_PSS_RSAE_SHA512,
    SIG_RSA_PSS_PSS_SHA256,
    SIG_RSA_PSS_PSS_SHA384,
    SIG_RSA_PSS_PSS_SHA512,
)

# TLS Alert Levels & Descriptions (RFC 8446 §6 + RFC 9849 §7.2)
ALERT_LEVEL_WARNING = 1
ALERT_LEVEL_FATAL = 2

ALERT_CLOSE_NOTIFY = 0
ALERT_UNEXPECTED_MESSAGE = 10
ALERT_BAD_RECORD_MAC = 20
ALERT_RECORD_OVERFLOW = 22
ALERT_HANDSHAKE_FAILURE = 40
ALERT_BAD_CERTIFICATE = 42
ALERT_CERTIFICATE_EXPIRED = 45
ALERT_ILLEGAL_PARAMETER = 47
ALERT_UNKNOWN_CA = 48
ALERT_DECODE_ERROR = 50
ALERT_DECRYPT_ERROR = 51
ALERT_PROTOCOL_VERSION = 70
ALERT_UNSUPPORTED_EXTENSION = 110
ALERT_MISSING_EXTENSION = 109
ALERT_ECH_REQUIRED = 121  # 0x79

# RFC 8446 §4.1.3 HelloRetryRequest special ServerHello.random sentinel
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

MAX_PLAINTEXT_RECORD_LEN = 16384
MAX_CIPHERTEXT_RECORD_LEN = 16384 + 256
MAX_HANDSHAKE_MSG_LEN = 256 * 1024
MAX_RECORD_SEQ = (1 << 64) - 1
_MAX_IGNORED_CCS = 4

_ALLOWED_SH_EXTENSIONS = frozenset((EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE))
_ALLOWED_HRR_EXTENSIONS = frozenset(
    (EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE, EXT_COOKIE, EXT_ENCRYPTED_CLIENT_HELLO)
)

# Cached default trust store keyed on (SSL_CERT_FILE, SSL_CERT_DIR)
_DEFAULT_STORE_CACHE: Optional[Tuple[Tuple[Optional[str], Optional[str]], Store]] = None


class TlsError(TunnelConnectionError):
    """Base error for TLS 1.3 protocol, record, handshake, or peer alert failures."""


class TlsAlertError(TlsError):
    """Raised when the TLS peer sends a fatal alert."""

    def __init__(self, level: int, description: int) -> None:
        super().__init__(f"TLS peer sent alert (level={level}, description={description})")
        self.level = level
        self.description = description


class EchConfigError(TunnelError):
    """Raised when an ECHConfigList is invalid or contains no compatible HPKE suite."""


class EchRejectedError(TunnelError):
    """Raised when the server rejects ECH (carrying verified ``retry_configs`` if supplied)."""

    def __init__(
        self,
        message: str,
        *,
        retry_configs: Optional[bytes] = None,
        public_name: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.retry_configs = retry_configs
        self.public_name = public_name


@dataclass(frozen=True)
class CipherSuiteSpec:
    """Parameters for a supported TLS 1.3 AEAD cipher suite."""

    code: int
    name: str
    hash_alg: hashes.HashAlgorithm
    hash_len: int
    key_len: int
    iv_len: int
    is_chacha: bool


CIPHER_SUITES: Dict[int, CipherSuiteSpec] = {
    TLS_AES_128_GCM_SHA256: CipherSuiteSpec(
        code=TLS_AES_128_GCM_SHA256,
        name="TLS_AES_128_GCM_SHA256",
        hash_alg=hashes.SHA256(),
        hash_len=32,
        key_len=16,
        iv_len=12,
        is_chacha=False,
    ),
    TLS_AES_256_GCM_SHA384: CipherSuiteSpec(
        code=TLS_AES_256_GCM_SHA384,
        name="TLS_AES_256_GCM_SHA384",
        hash_alg=hashes.SHA384(),
        hash_len=48,
        key_len=32,
        iv_len=12,
        is_chacha=False,
    ),
    TLS_CHACHA20_POLY1305_SHA256: CipherSuiteSpec(
        code=TLS_CHACHA20_POLY1305_SHA256,
        name="TLS_CHACHA20_POLY1305_SHA256",
        hash_alg=hashes.SHA256(),
        hash_len=32,
        key_len=32,
        iv_len=12,
        is_chacha=True,
    ),
}


# ---------------------------------------------------------------------------
# TLS 1.3 Key Schedule & Transcript Helpers (RFC 8446 §7)
# ---------------------------------------------------------------------------


def hash_bytes(hash_alg: hashes.HashAlgorithm, data: bytes) -> bytes:
    """Compute a single-shot hash digest using *hash_alg*."""
    digest = hashes.Hash(hash_alg)
    digest.update(data)
    return digest.finalize()


def hmac_bytes(hash_alg: hashes.HashAlgorithm, key: bytes, data: bytes) -> bytes:
    """Compute HMAC using *hash_alg*."""
    mac = crypto_hmac.HMAC(key, hash_alg)
    mac.update(data)
    return mac.finalize()


def hkdf_extract(hash_alg: hashes.HashAlgorithm, salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 ``HKDF-Extract(salt, IKM)``."""
    actual_salt = salt if salt else (b"\x00" * hash_alg.digest_size)
    return hmac_bytes(hash_alg, actual_salt, ikm)


def hkdf_expand_label(
    hash_alg: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    context: bytes,
    length: int,
) -> bytes:
    """RFC 8446 §7.1 ``HKDF-Expand-Label(Secret, Label, Context, Length)``."""
    full_label = b"tls13 " + label
    hkdf_label = (
        struct.pack("!H", length)
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    if length == 0:
        return b""
    return HKDFExpand(
        algorithm=hash_alg,
        length=length,
        info=hkdf_label,
    ).derive(secret)


def derive_secret(
    hash_alg: hashes.HashAlgorithm,
    secret: bytes,
    label: bytes,
    transcript_hash: bytes,
) -> bytes:
    """RFC 8446 §7.1 ``Derive-Secret(Secret, Label, Messages)`` given pre-hashed transcript."""
    return hkdf_expand_label(hash_alg, secret, label, transcript_hash, hash_alg.digest_size)


def derive_traffic_keys(spec: CipherSuiteSpec, traffic_secret: bytes) -> Tuple[bytes, bytes]:
    """Derive ``(key, iv)`` from a TLS 1.3 traffic secret (RFC 8446 §7.3)."""
    key = hkdf_expand_label(spec.hash_alg, traffic_secret, b"key", b"", spec.key_len)
    iv = hkdf_expand_label(spec.hash_alg, traffic_secret, b"iv", b"", spec.iv_len)
    return key, iv


def derive_finished_verify_data(
    hash_alg: hashes.HashAlgorithm,
    base_key: bytes,
    transcript_hash: bytes,
) -> bytes:
    """RFC 8446 §4.4.4 ``Finished`` verify_data computation."""
    finished_key = hkdf_expand_label(hash_alg, base_key, b"finished", b"", hash_alg.digest_size)
    return hmac_bytes(hash_alg, finished_key, transcript_hash)


def derive_next_traffic_secret(spec: CipherSuiteSpec, traffic_secret: bytes) -> bytes:
    """RFC 8446 §7.2 ``KeyUpdate`` next application traffic secret."""
    return hkdf_expand_label(spec.hash_alg, traffic_secret, b"traffic upd", b"", spec.hash_len)


def compute_handshake_secrets(
    spec: CipherSuiteSpec,
    shared_secret: bytes,
    th_server_hello: bytes,
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Compute ``(handshake_secret, client_hs_secret, server_hs_secret, master_secret)``."""
    zeros = b"\x00" * spec.hash_len
    empty_hash = hash_bytes(spec.hash_alg, b"")
    early_secret = hkdf_extract(spec.hash_alg, zeros, zeros)
    derived_early = derive_secret(spec.hash_alg, early_secret, b"derived", empty_hash)
    handshake_secret = hkdf_extract(spec.hash_alg, derived_early, shared_secret)

    client_hs = derive_secret(spec.hash_alg, handshake_secret, b"c hs traffic", th_server_hello)
    server_hs = derive_secret(spec.hash_alg, handshake_secret, b"s hs traffic", th_server_hello)

    derived_hs = derive_secret(spec.hash_alg, handshake_secret, b"derived", empty_hash)
    master_secret = hkdf_extract(spec.hash_alg, derived_hs, zeros)
    return handshake_secret, client_hs, server_hs, master_secret


def compute_app_secrets(
    spec: CipherSuiteSpec,
    master_secret: bytes,
    th_server_finished: bytes,
) -> Tuple[bytes, bytes]:
    """Compute ``(client_app_secret, server_app_secret)``."""
    client_app = derive_secret(spec.hash_alg, master_secret, b"c ap traffic", th_server_finished)
    server_app = derive_secret(spec.hash_alg, master_secret, b"s ap traffic", th_server_finished)
    return client_app, server_app


# ---------------------------------------------------------------------------
# TLS 1.3 Record Cipher (RFC 8446 §5.2 & §5.4)
# ---------------------------------------------------------------------------


class TlsRecordCipher:
    """Per-direction TLS 1.3 AEAD record protector with 64-bit sequence counter."""

    def __init__(self, spec: CipherSuiteSpec, traffic_secret: bytes) -> None:
        self.spec = spec
        self.traffic_secret = traffic_secret
        key, iv = derive_traffic_keys(spec, traffic_secret)
        self._iv = iv
        self._aead: Union[AESGCM, ChaCha20Poly1305] = (
            ChaCha20Poly1305(key) if spec.is_chacha else AESGCM(key)
        )
        self.seq = 0

    def update_keys(self) -> None:
        """Advance traffic secret per RFC 8446 §7.2 ``KeyUpdate`` and reset sequence counter."""
        self.traffic_secret = derive_next_traffic_secret(self.spec, self.traffic_secret)
        key, iv = derive_traffic_keys(self.spec, self.traffic_secret)
        self._iv = iv
        self._aead = ChaCha20Poly1305(key) if self.spec.is_chacha else AESGCM(key)
        self.seq = 0

    def _nonce(self) -> bytes:
        seq_bytes = self.seq.to_bytes(self.spec.iv_len, "big")
        return bytes(a ^ b for a, b in zip(self._iv, seq_bytes))

    def encrypt_record(self, inner_content_type: int, plaintext: bytes) -> bytes:
        """Encrypt a single TLS 1.3 ``TLSCiphertext`` record (including 5-byte header)."""
        if len(plaintext) > MAX_PLAINTEXT_RECORD_LEN:
            raise TlsError(f"outbound TLS plaintext exceeds {MAX_PLAINTEXT_RECORD_LEN} bytes")
        if self.seq >= MAX_RECORD_SEQ:
            raise TlsError("TLS record sequence number overflow")

        inner = plaintext + bytes([inner_content_type])
        ct_len = len(inner) + 16
        header = struct.pack("!BHH", CONTENT_APPLICATION_DATA, TLS_VERSION_1_2, ct_len)
        nonce = self._nonce()
        ciphertext = self._aead.encrypt(nonce, inner, header)
        self.seq += 1
        return header + ciphertext

    def decrypt_record(self, raw_header: bytes, ciphertext: bytes) -> Tuple[int, bytes]:
        """Decrypt a TLS 1.3 ``TLSCiphertext`` record, stripping trailing zero padding."""
        if len(raw_header) != 5:
            raise TlsError("invalid TLS record header length")
        if len(ciphertext) > MAX_CIPHERTEXT_RECORD_LEN:
            raise TlsError("TLS ciphertext record overflow")
        if len(ciphertext) < 17:  # at least 1 byte content type + 16 byte AEAD tag
            raise TlsError("TLS ciphertext record too short")
        if self.seq >= MAX_RECORD_SEQ:
            raise TlsError("TLS record sequence number overflow")

        nonce = self._nonce()
        try:
            inner = self._aead.decrypt(nonce, ciphertext, raw_header)
        except InvalidTag as exc:
            raise TlsError("TLS record AEAD decryption failed (bad_record_mac)") from exc
        self.seq += 1

        # RFC 8446 §5.4: strip trailing 0x00 padding bytes; last non-zero byte is inner content type.
        end = len(inner)
        while end > 0 and inner[end - 1] == 0:
            end -= 1
        if end == 0:
            raise TlsError("TLS inner plaintext contained only zero padding (unexpected_message)")
        inner_type = inner[end - 1]
        content = inner[: end - 1]
        if len(content) > MAX_PLAINTEXT_RECORD_LEN:
            raise TlsError("decrypted TLS inner plaintext exceeds 16384 bytes (record_overflow)")
        return inner_type, content


# ---------------------------------------------------------------------------
# Wire Encoding / Decoding & RFC 9849 ECH Construction Helpers
# ---------------------------------------------------------------------------


def _u24_pack(val: int) -> bytes:
    if val < 0 or val > 0xFFFFFF:
        raise TlsError(f"uint24 value out of range: {val}")
    return struct.pack("!I", val)[1:]


def _u24_unpack(buf: bytes, offset: int) -> int:
    return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]


def _pack_handshake(hs_type: int, body: bytes) -> bytes:
    return bytes([hs_type]) + _u24_pack(len(body)) + body


def _pack_plaintext_record(content_type: int, payload: bytes, legacy_version: int = TLS_VERSION_1_2) -> bytes:
    return struct.pack("!BHH", content_type, legacy_version, len(payload)) + payload


def _pack_ext(ext_type: int, ext_data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(ext_data)) + ext_data


def _encode_sni_extension(hostname: str) -> Tuple[bytes, bytes]:
    """Encode ``server_name`` extension payload, returning ``(ext_data, ascii_host_bytes)``."""
    ascii_host = normalize_hostname(hostname).encode("idna")
    entry = b"\x00" + struct.pack("!H", len(ascii_host)) + ascii_host
    return struct.pack("!H", len(entry)) + entry, ascii_host


def _encode_alpn_extension(protocols: Sequence[str]) -> bytes:
    items: List[bytes] = []
    for proto in protocols:
        pb = proto.encode("ascii")
        if not pb or len(pb) > 255:
            raise TlsError(f"invalid ALPN protocol name: {proto!r}")
        items.append(bytes([len(pb)]) + pb)
    body = b"".join(items)
    return struct.pack("!H", len(body)) + body


def _generate_key_share(
    group: int,
) -> Tuple[Union[x25519.X25519PrivateKey, ec.EllipticCurvePrivateKey], bytes]:
    """Generate an ephemeral TLS 1.3 key share for *group* -> ``(priv_key, pub_bytes)``."""
    if group == GROUP_X25519:
        sk = x25519.X25519PrivateKey.generate()
        return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if group == GROUP_SECP256R1:
        sk_ec = ec.generate_private_key(ec.SECP256R1())
        return sk_ec, sk_ec.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    raise TlsError(f"unsupported TLS 1.3 key share group: 0x{group:04x}")


def _compute_ecdhe_shared_secret(
    group: int,
    client_priv: Union[x25519.X25519PrivateKey, ec.EllipticCurvePrivateKey],
    server_pub_bytes: bytes,
) -> bytes:
    """Compute and strictly validate TLS 1.3 ECDHE shared secret."""
    if group == GROUP_X25519:
        if len(server_pub_bytes) != 32:
            raise TlsError(f"invalid server X25519 key share length: {len(server_pub_bytes)}")
        if hmac.compare_digest(server_pub_bytes, b"\x00" * 32):
            raise TlsError("rejected all-zero server X25519 key share")
        assert isinstance(client_priv, x25519.X25519PrivateKey)
        try:
            peer = x25519.X25519PublicKey.from_public_bytes(server_pub_bytes)
            ss = client_priv.exchange(peer)
        except Exception as exc:
            raise TlsError(f"X25519 key exchange failed: {exc}") from exc
        if len(ss) != 32 or hmac.compare_digest(ss, b"\x00" * 32):
            raise TlsError("X25519 key exchange produced all-zero shared secret")
        return ss

    if group == GROUP_SECP256R1:
        if len(server_pub_bytes) != 65 or server_pub_bytes[0] != 0x04:
            raise TlsError(f"invalid server P-256 key share encoding (len={len(server_pub_bytes)})")
        assert isinstance(client_priv, ec.EllipticCurvePrivateKey)
        try:
            peer_ec = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), server_pub_bytes)
            ss = client_priv.exchange(ec.ECDH(), peer_ec)
        except Exception as exc:
            raise TlsError(f"P-256 key exchange failed: {exc}") from exc
        if len(ss) != 32:
            raise TlsError(f"unexpected P-256 shared secret length: {len(ss)}")
        return ss

    raise TlsError(f"unsupported server key share group: 0x{group:04x}")


def pad_encoded_client_hello_inner(
    encoded_inner_raw: bytes,
    inner_sni_bytes: Optional[bytes],
    maximum_name_length: int,
) -> bytes:
    """Pad ``EncodedClientHelloInner`` per RFC 9849 §6.1.3.

    - ``L = maximum_name_length if maximum_name_length > 0 else 255``
    - ``name_pad = max(0, L - len(inner_sni_bytes))`` if SNI present, else ``L + 9``
    - ``align_pad = 31 - ((len_after_name_pad - 1) % 32)`` so final length is a multiple of 32.
    """
    max_len = maximum_name_length if maximum_name_length > 0 else 255
    if inner_sni_bytes:
        name_pad = max(0, max_len - len(inner_sni_bytes))
    else:
        name_pad = max_len + 9
    len_so_far = len(encoded_inner_raw) + name_pad
    align_pad = 31 - ((len_so_far - 1) % 32)
    return encoded_inner_raw + (b"\x00" * (name_pad + align_pad))


def build_client_hello_body(
    *,
    random_bytes: bytes,
    session_id: bytes,
    cipher_suites: Sequence[int],
    extensions: Sequence[Tuple[int, bytes]],
) -> bytes:
    """Build a TLS 1.3 ``ClientHello`` body (WITHOUT the 4-byte Handshake header)."""
    if len(random_bytes) != 32:
        raise TlsError("ClientHello random must be 32 bytes")
    if len(session_id) > 32:
        raise TlsError("ClientHello legacy_session_id must be <= 32 bytes")

    cs_wire = b"".join(struct.pack("!H", cs) for cs in cipher_suites)
    ext_wire = b"".join(_pack_ext(et, ed) for et, ed in extensions)
    return (
        struct.pack("!H", TLS_VERSION_1_2)
        + random_bytes
        + bytes([len(session_id)])
        + session_id
        + struct.pack("!H", len(cs_wire))
        + cs_wire
        + b"\x01\x00"  # legacy_compression_methods = [null]
        + struct.pack("!H", len(ext_wire))
        + ext_wire
    )


def build_ech_client_hello_pair(
    *,
    selected: SelectedEchConfig,
    hpke_sealer: HpkeSealer,
    enc_for_outer: bytes,
    real_host: str,
    inner_random: bytes,
    outer_random: bytes,
    session_id: bytes,
    inner_key_share: Tuple[int, bytes],
    outer_key_share: Tuple[int, bytes],
    alpn_protocols: Sequence[str] = ("http/1.1",),
    cookie: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """Construct ``(logical_inner_ch_msg, outer_ch_msg, outer_ch_aad)`` per RFC 9849 §5.1.

    - ``logical_inner_ch_msg`` includes the 4-byte Handshake header and shares ``session_id``
      with ``ClientHelloOuter`` (for the inner transcript).
    - ``EncodedClientHelloInner`` omits the 4-byte Handshake header, uses empty ``session_id``,
      and is zero-padded per §6.1.3 before HPKE sealing.
    - ``outer_ch_aad`` is ``ClientHelloOuter`` body WITHOUT the 4-byte Handshake header, with
      ``enc_for_outer`` populated (empty on CH2 after HRR) and ``payload`` zeroed.
    """
    sv_ext = struct.pack("!BH", 2, TLS_VERSION_1_3)
    groups_ext = struct.pack("!H", len(SUPPORTED_GROUPS) * 2) + b"".join(
        struct.pack("!H", g) for g in SUPPORTED_GROUPS
    )
    sigs_ext = struct.pack("!H", len(SUPPORTED_SIGNATURE_ALGORITHMS) * 2) + b"".join(
        struct.pack("!H", s) for s in SUPPORTED_SIGNATURE_ALGORITHMS
    )
    alpn_ext = _encode_alpn_extension(alpn_protocols) if alpn_protocols else None

    # --- Build ClientHelloInner extensions ---
    inner_exts: List[Tuple[int, bytes]] = []
    inner_sni_bytes: Optional[bytes] = None
    clean_real_host = normalize_hostname(real_host)
    if clean_real_host and not is_ip_literal(clean_real_host):
        sni_data, inner_sni_bytes = _encode_sni_extension(clean_real_host)
        inner_exts.append((EXT_SERVER_NAME, sni_data))

    inner_group, inner_pub = inner_key_share
    inner_ks_entry = struct.pack("!HH", inner_group, len(inner_pub)) + inner_pub
    inner_exts.append((EXT_SUPPORTED_VERSIONS, sv_ext))
    inner_exts.append((EXT_SUPPORTED_GROUPS, groups_ext))
    inner_exts.append((EXT_SIGNATURE_ALGORITHMS, sigs_ext))
    inner_exts.append((EXT_KEY_SHARE, struct.pack("!H", len(inner_ks_entry)) + inner_ks_entry))
    if alpn_ext is not None:
        inner_exts.append((EXT_ALPN, alpn_ext))
    if cookie is not None:
        inner_exts.append((EXT_COOKIE, struct.pack("!H", len(cookie)) + cookie))
    inner_exts.append((EXT_ENCRYPTED_CLIENT_HELLO, bytes([ECH_CLIENT_HELLO_INNER])))

    # Logical ClientHelloInner (for inner transcript: includes session_id + 4B handshake header)
    logical_inner_body = build_client_hello_body(
        random_bytes=inner_random,
        session_id=session_id,
        cipher_suites=SUPPORTED_CIPHER_SUITES,
        extensions=inner_exts,
    )
    logical_inner_msg = _pack_handshake(HS_CLIENT_HELLO, logical_inner_body)

    # EncodedClientHelloInner (for HPKE plaintext: empty session_id, NO 4B handshake header, padded)
    encoded_inner_raw = build_client_hello_body(
        random_bytes=inner_random,
        session_id=b"",
        cipher_suites=SUPPORTED_CIPHER_SUITES,
        extensions=inner_exts,
    )
    encoded_inner_padded = pad_encoded_client_hello_inner(
        encoded_inner_raw,
        inner_sni_bytes,
        selected.maximum_name_length,
    )
    payload_len = len(encoded_inner_padded) + HPKE_TAG_LEN

    # --- Build ClientHelloOuter extensions ---
    outer_sni_data, _ = _encode_sni_extension(selected.public_name)
    outer_group, outer_pub = outer_key_share
    outer_ks_entry = struct.pack("!HH", outer_group, len(outer_pub)) + outer_pub

    outer_base_exts: List[Tuple[int, bytes]] = [
        (EXT_SERVER_NAME, outer_sni_data),
        (EXT_SUPPORTED_VERSIONS, sv_ext),
        (EXT_SUPPORTED_GROUPS, groups_ext),
        (EXT_SIGNATURE_ALGORITHMS, sigs_ext),
        (EXT_KEY_SHARE, struct.pack("!H", len(outer_ks_entry)) + outer_ks_entry),
    ]
    if alpn_ext is not None:
        outer_base_exts.append((EXT_ALPN, alpn_ext))
    if cookie is not None:
        outer_base_exts.append((EXT_COOKIE, struct.pack("!H", len(cookie)) + cookie))

    ech_outer_prefix = (
        bytes([ECH_CLIENT_HELLO_OUTER])
        + struct.pack("!HHB", selected.kdf_id, selected.aead_id, selected.config_id)
        + struct.pack("!H", len(enc_for_outer))
        + enc_for_outer
        + struct.pack("!H", payload_len)
    )

    # ClientHelloOuterAAD: ClientHelloOuter body WITHOUT 4-byte Handshake header,
    # with enc populated and ONLY payload zeroed to payload_len bytes.
    aad_exts = outer_base_exts + [
        (EXT_ENCRYPTED_CLIENT_HELLO, ech_outer_prefix + (b"\x00" * payload_len))
    ]
    outer_aad = build_client_hello_body(
        random_bytes=outer_random,
        session_id=session_id,
        cipher_suites=SUPPORTED_CIPHER_SUITES,
        extensions=aad_exts,
    )

    ciphertext = hpke_sealer.seal(outer_aad, encoded_inner_padded)
    if len(ciphertext) != payload_len:
        raise TlsError(f"unexpected HPKE ciphertext length: {len(ciphertext)} != {payload_len}")

    real_exts = outer_base_exts + [(EXT_ENCRYPTED_CLIENT_HELLO, ech_outer_prefix + ciphertext)]
    outer_body = build_client_hello_body(
        random_bytes=outer_random,
        session_id=session_id,
        cipher_suites=SUPPORTED_CIPHER_SUITES,
        extensions=real_exts,
    )
    outer_msg = _pack_handshake(HS_CLIENT_HELLO, outer_body)
    return logical_inner_msg, outer_msg, outer_aad


def compute_ech_accept_confirmation(
    spec: CipherSuiteSpec,
    inner_random: bytes,
    inner_transcript_before_sh: bytes,
    raw_server_hello_msg: bytes,
) -> bytes:
    """RFC 9849 §7.2 ServerHello ECH acceptance confirmation (8 bytes)."""
    if len(raw_server_hello_msg) < 38:
        raise TlsError("ServerHello message too short for ECH confirmation")
    sh_zeroed = bytearray(raw_server_hello_msg)
    # bytes [0..4] = Handshake header, [4..6] = legacy_version, [6..38] = 32B random;
    # last 8 bytes of random are at [30..38].
    sh_zeroed[30:38] = b"\x00" * 8
    th = hash_bytes(spec.hash_alg, inner_transcript_before_sh + bytes(sh_zeroed))
    accept_secret = hkdf_extract(spec.hash_alg, b"\x00" * spec.hash_len, inner_random)
    return hkdf_expand_label(spec.hash_alg, accept_secret, b"ech accept confirmation", th, 8)


def compute_hrr_ech_accept_confirmation(
    spec: CipherSuiteSpec,
    inner_random: bytes,
    inner_ch1_msg: bytes,
    raw_hrr_msg: bytes,
    ech_ext_val_offset: int,
) -> bytes:
    """RFC 9849 §7.2.1 HelloRetryRequest ECH acceptance confirmation (8 bytes)."""
    if ech_ext_val_offset < 0 or ech_ext_val_offset + 8 > len(raw_hrr_msg):
        raise TlsError("invalid HRR ECH extension offset")
    ch1_hash = hash_bytes(spec.hash_alg, inner_ch1_msg)
    message_hash = bytes([HS_MESSAGE_HASH, 0x00, 0x00, spec.hash_len]) + ch1_hash
    hrr_zeroed = bytearray(raw_hrr_msg)
    hrr_zeroed[ech_ext_val_offset : ech_ext_val_offset + 8] = b"\x00" * 8
    th = hash_bytes(spec.hash_alg, message_hash + bytes(hrr_zeroed))
    accept_secret = hkdf_extract(spec.hash_alg, b"\x00" * spec.hash_len, inner_random)
    return hkdf_expand_label(spec.hash_alg, accept_secret, b"hrr ech accept confirmation", th, 8)


# ---------------------------------------------------------------------------
# Handshake Message Parsers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParsedServerHello:
    raw_msg: bytes
    random: bytes
    session_id_echo: bytes
    cipher_suite: int
    extensions: Dict[int, bytes]
    ext_val_offsets: Dict[int, int]  # offset of ext_data inside raw_msg
    is_hrr: bool


def _parse_server_hello(raw_msg: bytes) -> ParsedServerHello:
    if len(raw_msg) < 4 + 2 + 32 + 1 + 2 + 1 + 2:
        raise TlsError("truncated ServerHello message")
    if raw_msg[0] != HS_SERVER_HELLO:
        raise TlsError(f"expected ServerHello (0x02), got 0x{raw_msg[0]:02x}")
    body_len = _u24_unpack(raw_msg, 1)
    if 4 + body_len != len(raw_msg):
        raise TlsError("ServerHello length mismatch")

    pos = 4
    (legacy_ver,) = struct.unpack_from("!H", raw_msg, pos)
    pos += 2
    if legacy_ver != TLS_VERSION_1_2:
        raise TlsError(f"unexpected ServerHello legacy_version 0x{legacy_ver:04x}")

    server_random = raw_msg[pos : pos + 32]
    pos += 32

    sid_len = raw_msg[pos]
    pos += 1
    if sid_len > 32 or pos + sid_len + 5 > len(raw_msg):
        raise TlsError("invalid ServerHello legacy_session_id_echo")
    session_id_echo = raw_msg[pos : pos + sid_len]
    pos += sid_len

    cipher_suite, comp_method = struct.unpack_from("!HB", raw_msg, pos)
    pos += 3
    if comp_method != 0:
        raise TlsError(f"non-zero ServerHello compression method: {comp_method}")

    (ext_total_len,) = struct.unpack_from("!H", raw_msg, pos)
    pos += 2
    if pos + ext_total_len != len(raw_msg):
        raise TlsError("ServerHello extensions length mismatch")

    extensions: Dict[int, bytes] = {}
    ext_val_offsets: Dict[int, int] = {}
    while pos < len(raw_msg):
        if pos + 4 > len(raw_msg):
            raise TlsError("truncated ServerHello extension header")
        ext_type, ext_len = struct.unpack_from("!HH", raw_msg, pos)
        pos += 4
        if pos + ext_len > len(raw_msg):
            raise TlsError("truncated ServerHello extension data")
        if ext_type in extensions:
            raise TlsError(f"duplicate ServerHello extension 0x{ext_type:04x}")
        ext_val_offsets[ext_type] = pos
        extensions[ext_type] = raw_msg[pos : pos + ext_len]
        pos += ext_len

    sv = extensions.get(EXT_SUPPORTED_VERSIONS)
    if sv is None or len(sv) != 2 or struct.unpack("!H", sv)[0] != TLS_VERSION_1_3:
        raise TlsError("server did not negotiate TLS 1.3 (protocol_version)")

    return ParsedServerHello(
        raw_msg=raw_msg,
        random=server_random,
        session_id_echo=session_id_echo,
        cipher_suite=cipher_suite,
        extensions=extensions,
        ext_val_offsets=ext_val_offsets,
        is_hrr=hmac.compare_digest(server_random, HRR_RANDOM),
    )


def _parse_encrypted_extensions(body: bytes) -> Dict[int, bytes]:
    if len(body) < 2:
        raise TlsError("truncated EncryptedExtensions")
    (ext_len,) = struct.unpack_from("!H", body, 0)
    if 2 + ext_len != len(body):
        raise TlsError("EncryptedExtensions length mismatch")
    pos = 2
    exts: Dict[int, bytes] = {}
    while pos < len(body):
        if pos + 4 > len(body):
            raise TlsError("truncated EncryptedExtensions entry")
        etype, elen = struct.unpack_from("!HH", body, pos)
        pos += 4
        if pos + elen > len(body):
            raise TlsError("truncated EncryptedExtensions entry data")
        if etype in exts:
            raise TlsError(f"duplicate EncryptedExtensions entry 0x{etype:04x}")
        exts[etype] = body[pos : pos + elen]
        pos += elen
    return exts


def _parse_certificate_message(body: bytes) -> List[x509.Certificate]:
    if len(body) < 4:
        raise TlsError("truncated Certificate message")
    ctx_len = body[0]
    if ctx_len != 0:
        raise TlsError(f"server Certificate message has non-empty request context ({ctx_len})")
    list_len = _u24_unpack(body, 1)
    if 4 + list_len != len(body):
        raise TlsError("Certificate message length mismatch")
    pos = 4
    certs: List[x509.Certificate] = []
    while pos < len(body):
        if pos + 3 > len(body):
            raise TlsError("truncated CertificateEntry length")
        cert_len = _u24_unpack(body, pos)
        pos += 3
        if cert_len == 0 or pos + cert_len + 2 > len(body):
            raise TlsError("truncated CertificateEntry data")
        cert_der = body[pos : pos + cert_len]
        pos += cert_len
        (ext_len,) = struct.unpack_from("!H", body, pos)
        pos += 2
        if pos + ext_len > len(body):
            raise TlsError("truncated CertificateEntry extensions")
        pos += ext_len
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
                certs.append(x509.load_der_x509_certificate(cert_der))
        except Exception as exc:
            raise TlsError(f"failed parsing server X.509 certificate: {exc}") from exc
    if not certs:
        raise TlsError("server sent empty Certificate list")
    return certs


def verify_certificate_verify(
    leaf_cert: x509.Certificate,
    transcript_hash: bytes,
    cv_body: bytes,
) -> int:
    """Verify TLS 1.3 ``CertificateVerify`` signature (RFC 8446 §4.4.3). Returns signature scheme."""
    if len(cv_body) < 4:
        raise TlsError("truncated CertificateVerify message")
    scheme, sig_len = struct.unpack_from("!HH", cv_body, 0)
    if 4 + sig_len != len(cv_body):
        raise TlsError("CertificateVerify signature length mismatch")
    signature = cv_body[4:]

    signed_content = (b"\x20" * 64) + b"TLS 1.3, server CertificateVerify\x00" + transcript_hash
    pub_key = leaf_cert.public_key()

    try:
        if scheme in (SIG_RSA_PSS_RSAE_SHA256, SIG_RSA_PSS_PSS_SHA256):
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise TlsError("RSA-PSS-SHA256 CertificateVerify with non-RSA key")
            pub_key.verify(
                signature,
                signed_content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        elif scheme in (SIG_RSA_PSS_RSAE_SHA384, SIG_RSA_PSS_PSS_SHA384):
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise TlsError("RSA-PSS-SHA384 CertificateVerify with non-RSA key")
            pub_key.verify(
                signature,
                signed_content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
                hashes.SHA384(),
            )
        elif scheme in (SIG_RSA_PSS_RSAE_SHA512, SIG_RSA_PSS_PSS_SHA512):
            if not isinstance(pub_key, rsa.RSAPublicKey):
                raise TlsError("RSA-PSS-SHA512 CertificateVerify with non-RSA key")
            pub_key.verify(
                signature,
                signed_content,
                padding.PSS(mgf=padding.MGF1(hashes.SHA512()), salt_length=64),
                hashes.SHA512(),
            )
        elif scheme == SIG_ECDSA_SECP256R1_SHA256:
            if not isinstance(pub_key, ec.EllipticCurvePublicKey) or not isinstance(
                pub_key.curve, ec.SECP256R1
            ):
                raise TlsError("ECDSA-P256-SHA256 CertificateVerify with mismatched key curve")
            pub_key.verify(signature, signed_content, ec.ECDSA(hashes.SHA256()))
        elif scheme == SIG_ECDSA_SECP384R1_SHA384:
            if not isinstance(pub_key, ec.EllipticCurvePublicKey) or not isinstance(
                pub_key.curve, ec.SECP384R1
            ):
                raise TlsError("ECDSA-P384-SHA384 CertificateVerify with mismatched key curve")
            pub_key.verify(signature, signed_content, ec.ECDSA(hashes.SHA384()))
        elif scheme == SIG_ED25519:
            if not isinstance(pub_key, ed25519.Ed25519PublicKey):
                raise TlsError("Ed25519 CertificateVerify with non-Ed25519 key")
            pub_key.verify(signature, signed_content)
        else:
            raise TlsError(f"unsupported CertificateVerify signature scheme: 0x{scheme:04x}")
    except InvalidSignature as exc:
        raise TlsError(f"invalid server CertificateVerify signature (0x{scheme:04x})") from exc
    except TlsError:
        raise
    except Exception as exc:
        raise TlsError(f"CertificateVerify verification error: {exc}") from exc

    return scheme


# ---------------------------------------------------------------------------
# Strict RFC 5280 X.509 Trust Store & PolicyBuilder Verification
# ---------------------------------------------------------------------------


def load_root_store(base_ssl_context: Optional[ssl.SSLContext] = None) -> Store:
    """Load trusted root CA certificates into a ``cryptography.x509.verification.Store``.

    Uses ``base_ssl_context`` if provided, otherwise ``ssl.create_default_context()``
    (honoring ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``), falling back to ``certifi`` if empty.
    """
    global _DEFAULT_STORE_CACHE

    if base_ssl_context is None:
        env_key = (os.environ.get("SSL_CERT_FILE"), os.environ.get("SSL_CERT_DIR"))
        if _DEFAULT_STORE_CACHE is not None and _DEFAULT_STORE_CACHE[0] == env_key:
            return _DEFAULT_STORE_CACHE[1]
        ctx = ssl.create_default_context()
    else:
        env_key = (None, None)
        ctx = base_ssl_context

    certs: List[x509.Certificate] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        for der in ctx.get_ca_certs(binary_form=True):
            try:
                certs.append(x509.load_der_x509_certificate(der))
            except Exception:
                continue

        if not certs and base_ssl_context is None:
            try:
                import certifi  # type: ignore[import-not-found]

                pem_data = Path(certifi.where()).read_bytes()
                certs.extend(x509.load_pem_x509_certificates(pem_data))
            except Exception:
                pass

    if not certs:
        raise ssl.SSLCertVerificationError("no trusted root CA certificates available")

    store = Store(certs)
    if base_ssl_context is None:
        _DEFAULT_STORE_CACHE = (env_key, store)
    return store


def verify_server_certificate_chain(
    certs: Sequence[x509.Certificate],
    expected_hostname: str,
    *,
    store: Store,
    verification_time: Optional[datetime.datetime] = None,
) -> List[x509.Certificate]:
    """Strictly verify a server X.509 certificate chain and hostname via ``PolicyBuilder``."""
    if not certs:
        raise ssl.SSLCertVerificationError("empty server certificate chain")

    cleaned = normalize_hostname(expected_hostname)
    if not cleaned:
        raise ssl.SSLCertVerificationError("cannot verify certificate against empty hostname")

    if is_ip_literal(cleaned):
        ip_str = cleaned.split("%", 1)[0]
        subject: Union[x509.DNSName, x509.IPAddress] = x509.IPAddress(ipaddress.ip_address(ip_str))
    else:
        try:
            ascii_host = cleaned.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ssl.SSLCertVerificationError(f"invalid hostname {expected_hostname!r}: {exc}") from exc
        subject = x509.DNSName(ascii_host)

    builder = PolicyBuilder().store(store)
    if verification_time is not None:
        builder = builder.time(verification_time)
    verifier = builder.build_server_verifier(subject)

    leaf = certs[0]
    intermediates = list(certs[1:])
    try:
        return verifier.verify(leaf, intermediates)
    except VerificationError as exc:
        raise ssl.SSLCertVerificationError(
            f"X.509 certificate verification failed for {expected_hostname!r}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Internal Asyncio Raw TCP Protocol + Tls13EchTransport(asyncio.Transport)
# ---------------------------------------------------------------------------


class _RawTcpProtocol(asyncio.Protocol):
    """Bridges an ``asyncio.Transport`` to the TLS 1.3 handshake reader and ``Tls13EchTransport``."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self.transport: Optional[asyncio.Transport] = None
        self.buf = bytearray()
        self.eof = False
        self.closed = False
        self.close_exc: Optional[BaseException] = None
        self._waiter: Optional[asyncio.Future[None]] = None
        self._tls_transport: Optional[Tls13EchTransport] = None

    def _wake(self) -> None:
        waiter = self._waiter
        if waiter is not None and not waiter.done():
            self._waiter = None
            waiter.set_result(None)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def data_received(self, data: bytes) -> None:
        if self._tls_transport is not None:
            self._tls_transport._on_raw_data(data)
            return
        self.buf.extend(data)
        self._wake()

    def eof_received(self) -> Optional[bool]:
        self.eof = True
        if self._tls_transport is not None:
            return self._tls_transport._on_raw_eof()
        self._wake()
        return True

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.closed = True
        self.close_exc = exc
        if self._tls_transport is not None:
            self._tls_transport._on_raw_connection_lost(exc)
            return
        self._wake()

    def pause_writing(self) -> None:
        if self._tls_transport is not None:
            self._tls_transport._on_raw_pause_writing()

    def resume_writing(self) -> None:
        if self._tls_transport is not None:
            self._tls_transport._on_raw_resume_writing()

    async def read_exact(self, n: int) -> bytes:
        """Read exactly *n* bytes during the handshake phase."""
        while len(self.buf) < n:
            if self.eof or self.closed:
                if self.close_exc is not None:
                    raise TlsError(f"connection closed during TLS handshake: {self.close_exc}") from self.close_exc
                raise TlsError("unexpected EOF during TLS handshake")
            waiter: asyncio.Future[None] = self._loop.create_future()
            self._waiter = waiter
            try:
                await waiter
            finally:
                if self._waiter is waiter:
                    self._waiter = None
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def attach_tls_transport(self, tls_transport: Tls13EchTransport) -> bytes:
        """Hand over ownership to *tls_transport*, returning any buffered unread bytes."""
        self._tls_transport = tls_transport
        leftover = bytes(self.buf)
        self.buf.clear()
        return leftover


class Tls13EchTransport(asyncio.Transport):
    """``asyncio.Transport`` backed by our pure-Python TLS 1.3 + ECH record layer.

    Implements every method expected by ``websockets.asyncio.client.Connection`` and general
    ``asyncio.Protocol`` consumers without spawning background tasks or using ``add_reader``.
    """

    def __init__(
        self,
        *,
        loop: asyncio.AbstractEventLoop,
        raw_transport: asyncio.Transport,
        raw_protocol: _RawTcpProtocol,
        send_cipher: TlsRecordCipher,
        recv_cipher: TlsRecordCipher,
        cipher_spec: CipherSuiteSpec,
        outer_sni: str,
        real_host: str,
        alpn: Optional[str] = None,
        peer_cert: Optional[x509.Certificate] = None,
    ) -> None:
        super().__init__()
        self._loop = loop
        self._raw_transport = raw_transport
        self._raw_protocol = raw_protocol
        self._send_cipher = send_cipher
        self._recv_cipher = recv_cipher
        self._cipher_spec = cipher_spec
        self._outer_sni = outer_sni
        self._real_host = real_host
        self._alpn = alpn
        self._peer_cert = peer_cert

        self._protocol: Optional[asyncio.BaseProtocol] = None
        self._recv_buf = bytearray()
        self._post_hs_buf = bytearray()
        self._closing = False
        self._close_notify_sent = False
        self._peer_eof_delivered = False
        self._connection_lost_called = False
        self._pending_error: Optional[Exception] = None

    @property
    def outer_sni(self) -> str:
        return self._outer_sni

    @property
    def real_host(self) -> str:
        return self._real_host

    @property
    def alpn_protocol(self) -> Optional[str]:
        return self._alpn

    @property
    def cipher_name(self) -> str:
        return self._cipher_spec.name

    # --- asyncio.Transport interface ---

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "tls_version":
            return "TLSv1.3"
        if name == "ech_status":
            return "accepted"
        if name == "ech_outer_sni":
            return self._outer_sni
        if name == "alpn":
            return self._alpn
        if name == "cipher":
            return (self._cipher_spec.name, "TLSv1.3", self._cipher_spec.key_len * 8)
        if name == "peercert":
            return self._peer_cert
        return self._raw_transport.get_extra_info(name, default)

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        self._protocol = protocol

    def get_protocol(self) -> asyncio.BaseProtocol:
        assert self._protocol is not None
        return self._protocol

    def is_closing(self) -> bool:
        return self._closing or self._raw_transport.is_closing()

    def pause_reading(self) -> None:
        self._raw_transport.pause_reading()

    def resume_reading(self) -> None:
        self._raw_transport.resume_reading()

    def is_reading(self) -> bool:
        return self._raw_transport.is_reading()

    def set_write_buffer_limits(
        self,
        high: Optional[int] = None,
        low: Optional[int] = None,
    ) -> None:
        self._raw_transport.set_write_buffer_limits(high=high, low=low)

    def get_write_buffer_size(self) -> int:
        return self._raw_transport.get_write_buffer_size()

    def get_write_buffer_limits(self) -> Tuple[int, int]:
        return self._raw_transport.get_write_buffer_limits()

    def can_write_eof(self) -> bool:
        return False

    def write_eof(self) -> None:
        # Matches asyncio SSLTransport behavior: TLS close is performed via close_notify on close().
        pass

    def write(self, data: Union[bytes, bytearray, memoryview]) -> None:
        if self._closing or self._raw_transport.is_closing():
            return
        raw = bytes(data)
        if not raw:
            return
        # Chunk outbound application data to <= 16384 bytes per TLS 1.3 record.
        pos = 0
        total = len(raw)
        while pos < total:
            chunk = raw[pos : pos + MAX_PLAINTEXT_RECORD_LEN]
            pos += len(chunk)
            try:
                record = self._send_cipher.encrypt_record(CONTENT_APPLICATION_DATA, chunk)
            except Exception as exc:
                self._fail_and_abort(exc)
                return
            self._raw_transport.write(record)

    def writelines(self, list_of_data: Any) -> None:
        for item in list_of_data:
            self.write(item)

    def _send_alert(self, level: int, description: int) -> None:
        if self._raw_transport.is_closing():
            return
        try:
            payload = bytes([level, description])
            record = self._send_cipher.encrypt_record(CONTENT_ALERT, payload)
            self._raw_transport.write(record)
        except Exception:
            pass

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        if not self._close_notify_sent:
            self._close_notify_sent = True
            self._send_alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY)
        self._raw_transport.close()

    def abort(self) -> None:
        self._closing = True
        self._raw_transport.abort()

    # --- Internal callbacks from _RawTcpProtocol ---

    def _fail_and_abort(self, exc: Exception, *, alert_desc: Optional[int] = None) -> None:
        if self._pending_error is None:
            self._pending_error = exc
        if alert_desc is not None and not self._closing:
            self._send_alert(ALERT_LEVEL_FATAL, alert_desc)
        self._closing = True
        self._raw_transport.abort()

    def _on_raw_pause_writing(self) -> None:
        if self._protocol is not None:
            self._protocol.pause_writing()

    def _on_raw_resume_writing(self) -> None:
        if self._protocol is not None:
            self._protocol.resume_writing()

    def _on_raw_data(self, data: bytes) -> None:
        if not data or self._closing or self._pending_error is not None:
            return
        self._recv_buf.extend(data)
        if self._protocol is None:
            return
        self._drain_records()

    def _drain_records(self) -> None:
        while len(self._recv_buf) >= 5:
            if self._closing or self._pending_error is not None:
                return
            rec_type, _legacy_ver, rec_len = struct.unpack_from("!BHH", self._recv_buf, 0)
            if rec_len > MAX_CIPHERTEXT_RECORD_LEN:
                self._fail_and_abort(
                    TlsError(f"TLS record length {rec_len} exceeds maximum"),
                    alert_desc=ALERT_RECORD_OVERFLOW,
                )
                return
            if len(self._recv_buf) < 5 + rec_len:
                return

            raw_hdr = bytes(self._recv_buf[:5])
            rec_body = bytes(self._recv_buf[5 : 5 + rec_len])
            del self._recv_buf[: 5 + rec_len]

            # RFC 8446 §5/§6: post-handshake records MUST be encrypted TLSCiphertext (0x17);
            # plaintext alerts (e.g. unauthenticated close_notify) MUST be rejected!
            if rec_type != CONTENT_APPLICATION_DATA:
                self._fail_and_abort(
                    TlsError(f"unexpected post-handshake TLS record type 0x{rec_type:02x}"),
                    alert_desc=ALERT_UNEXPECTED_MESSAGE,
                )
                return

            try:
                inner_type, content = self._recv_cipher.decrypt_record(raw_hdr, rec_body)
            except Exception as exc:
                self._fail_and_abort(
                    exc if isinstance(exc, Exception) else TlsError(str(exc)),
                    alert_desc=ALERT_BAD_RECORD_MAC,
                )
                return

            if inner_type == CONTENT_APPLICATION_DATA:
                if self._post_hs_buf:
                    self._fail_and_abort(
                        TlsError("application data interleaved with fragmented post-handshake message"),
                        alert_desc=ALERT_UNEXPECTED_MESSAGE,
                    )
                    return
                if content and self._protocol is not None and hasattr(self._protocol, "data_received"):
                    self._protocol.data_received(content)  # type: ignore[attr-defined]
            elif inner_type == CONTENT_HANDSHAKE:
                if not content:
                    self._fail_and_abort(
                        TlsError("received zero-length post-handshake Handshake fragment"),
                        alert_desc=ALERT_UNEXPECTED_MESSAGE,
                    )
                    return
                self._handle_post_handshake(content)
            elif inner_type == CONTENT_ALERT:
                if self._post_hs_buf:
                    self._fail_and_abort(
                        TlsError("alert interleaved with fragmented post-handshake message"),
                        alert_desc=ALERT_UNEXPECTED_MESSAGE,
                    )
                    return
                if len(content) != 2:
                    self._fail_and_abort(
                        TlsError("malformed TLS alert record"),
                        alert_desc=ALERT_DECODE_ERROR,
                    )
                    return
                self._handle_alert(content[0], content[1])
                if self._peer_eof_delivered or self._closing or self._pending_error is not None:
                    return
            else:
                self._fail_and_abort(
                    TlsError(f"unexpected TLS inner content type 0x{inner_type:02x}"),
                    alert_desc=ALERT_UNEXPECTED_MESSAGE,
                )
                return

    def _handle_post_handshake(self, content: bytes) -> None:
        self._post_hs_buf.extend(content)
        while len(self._post_hs_buf) >= 4:
            hs_type = self._post_hs_buf[0]
            hs_len = _u24_unpack(self._post_hs_buf, 1)
            if hs_len > MAX_HANDSHAKE_MSG_LEN:
                self._fail_and_abort(
                    TlsError(f"oversized post-handshake message ({hs_len} bytes)"),
                    alert_desc=ALERT_DECODE_ERROR,
                )
                return
            if len(self._post_hs_buf) < 4 + hs_len:
                return
            hs_body = bytes(self._post_hs_buf[4 : 4 + hs_len])
            del self._post_hs_buf[: 4 + hs_len]

            if hs_type == HS_NEW_SESSION_TICKET:
                # RFC 8446 §4.6.1: safely ignore server session tickets.
                continue
            if hs_type == HS_KEY_UPDATE:
                if len(hs_body) != 1 or hs_body[0] not in (0, 1):
                    self._fail_and_abort(
                        TlsError("invalid KeyUpdate request_update value"),
                        alert_desc=ALERT_ILLEGAL_PARAMETER,
                    )
                    return
                # RFC 8446 §5.1: KeyUpdate MUST NOT be coalesced with trailing handshake bytes
                # in the same record across a key change boundary.
                if self._post_hs_buf:
                    self._fail_and_abort(
                        TlsError("unexpected trailing handshake bytes across KeyUpdate key change"),
                        alert_desc=ALERT_UNEXPECTED_MESSAGE,
                    )
                    return
                # RFC 8446 §4.6.3: update peer receive keys immediately.
                self._recv_cipher.update_keys()
                if hs_body[0] == 1:
                    # update_requested: send KeyUpdate(update_not_requested=0) under OLD keys,
                    # then update our own sending keys immediately.
                    ku_msg = _pack_handshake(HS_KEY_UPDATE, b"\x00")
                    try:
                        rec = self._send_cipher.encrypt_record(CONTENT_HANDSHAKE, ku_msg)
                        if not self._raw_transport.is_closing():
                            self._raw_transport.write(rec)
                        self._send_cipher.update_keys()
                    except Exception as exc:
                        self._fail_and_abort(exc)
                        return
                continue

            self._fail_and_abort(
                TlsError(f"unsupported post-handshake message type 0x{hs_type:02x}"),
                alert_desc=ALERT_UNEXPECTED_MESSAGE,
            )
            return

    def _handle_alert(self, level: int, description: int) -> None:
        if description == ALERT_CLOSE_NOTIFY:
            if not self._peer_eof_delivered:
                self._peer_eof_delivered = True
                keep_open = False
                if self._protocol is not None and hasattr(self._protocol, "eof_received"):
                    keep_open = bool(self._protocol.eof_received())  # type: ignore[attr-defined]
                if not keep_open:
                    self.close()
            return

        self._fail_and_abort(TlsAlertError(level, description))

    def _on_raw_eof(self) -> bool:
        if not self._peer_eof_delivered and self._protocol is not None and hasattr(self._protocol, "eof_received"):
            self._peer_eof_delivered = True
            self._protocol.eof_received()  # type: ignore[attr-defined]
        return False

    def _on_raw_connection_lost(self, exc: Optional[Exception]) -> None:
        if self._connection_lost_called:
            return
        self._connection_lost_called = True
        self._closing = True
        final_exc = self._pending_error if self._pending_error is not None else exc
        if self._protocol is not None:
            self._protocol.connection_lost(final_exc)

    def flush_initial_bytes(self, initial_bytes: bytes) -> None:
        """Process any buffered post-handshake bytes received before ``connection_made``."""
        if initial_bytes:
            self._on_raw_data(initial_bytes)
        if self._raw_protocol.eof and not self._peer_eof_delivered:
            self._on_raw_eof()
        if self._raw_protocol.closed and not self._connection_lost_called:
            exc = self._raw_protocol.close_exc
            self._on_raw_connection_lost(exc if isinstance(exc, Exception) else None)


# ---------------------------------------------------------------------------
# TLS 1.3 + RFC 9849 ECH Handshake Driver + 1-Shot retry_configs Retry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tls13EchHandshakeResult:
    """Result of a successful TLS 1.3 ECH handshake."""

    transport: Tls13EchTransport
    ech_status: str  # "accepted"
    outer_sni: str
    resolved_ip: str
    retried: bool
    cipher_suite: str
    alpn: Optional[str]
    tls_version: str = "TLSv1.3"


class _HandshakeReader:
    """Reads TLS 1.3 plaintext/encrypted records & reassembles fragmented handshake messages."""

    def __init__(self, raw_proto: _RawTcpProtocol) -> None:
        self._raw = raw_proto
        self.recv_cipher: Optional[TlsRecordCipher] = None
        self.hs_buf = bytearray()
        self._ccs_count = 0

    async def _read_next_record(self) -> Tuple[int, bytes]:
        while True:
            raw_hdr = await self._raw.read_exact(5)
            rec_type, _legacy_ver, rec_len = struct.unpack("!BHH", raw_hdr)
            max_len = MAX_CIPHERTEXT_RECORD_LEN if self.recv_cipher is not None else MAX_PLAINTEXT_RECORD_LEN
            if rec_len > max_len:
                raise TlsError(f"TLS record length {rec_len} exceeds limit ({max_len})")
            rec_body = await self._raw.read_exact(rec_len)

            # RFC 8446 §5: ignore middlebox ChangeCipherSpec records during handshake.
            if rec_type == CONTENT_CHANGE_CIPHER_SPEC:
                if rec_body != b"\x01":
                    raise TlsError("invalid ChangeCipherSpec payload")
                self._ccs_count += 1
                if self._ccs_count > _MAX_IGNORED_CCS:
                    raise TlsError("too many ChangeCipherSpec records during handshake")
                continue

            if self.recv_cipher is None:
                if rec_type == CONTENT_ALERT:
                    if len(rec_body) != 2:
                        raise TlsError("malformed plaintext TLS alert")
                    raise TlsAlertError(rec_body[0], rec_body[1])
                return rec_type, rec_body

            # Encrypted handshake flight
            if rec_type == CONTENT_ALERT:
                if len(rec_body) != 2:
                    raise TlsError("malformed plaintext TLS alert")
                raise TlsAlertError(rec_body[0], rec_body[1])
            if rec_type != CONTENT_APPLICATION_DATA:
                raise TlsError(f"expected encrypted TLS record (0x17), got 0x{rec_type:02x}")

            inner_type, content = self.recv_cipher.decrypt_record(raw_hdr, rec_body)
            if inner_type == CONTENT_ALERT:
                if len(content) != 2:
                    raise TlsError("malformed encrypted TLS alert")
                raise TlsAlertError(content[0], content[1])
            return inner_type, content

    async def read_handshake_message(self) -> Tuple[int, bytes, bytes]:
        """Read next complete handshake message -> ``(hs_type, hs_body, raw_hs_msg)``."""
        while True:
            if len(self.hs_buf) >= 4:
                hs_type = self.hs_buf[0]
                hs_len = _u24_unpack(self.hs_buf, 1)
                if hs_len > MAX_HANDSHAKE_MSG_LEN:
                    raise TlsError(f"handshake message too large ({hs_len} bytes)")
                if len(self.hs_buf) >= 4 + hs_len:
                    raw_msg = bytes(self.hs_buf[: 4 + hs_len])
                    hs_body = raw_msg[4:]
                    del self.hs_buf[: 4 + hs_len]
                    return hs_type, hs_body, raw_msg

            content_type, payload = await self._read_next_record()
            if content_type != CONTENT_HANDSHAKE:
                raise TlsError(
                    f"expected Handshake record (0x16), got content type 0x{content_type:02x}"
                )
            if not payload:
                raise TlsError("received zero-length Handshake fragment")
            self.hs_buf.extend(payload)


def _send_handshake_alert(
    raw_transport: asyncio.Transport,
    send_cipher: Optional[TlsRecordCipher],
    description: int,
) -> None:
    if raw_transport.is_closing():
        return
    try:
        payload = bytes([ALERT_LEVEL_FATAL, description])
        if send_cipher is not None:
            raw_transport.write(send_cipher.encrypt_record(CONTENT_ALERT, payload))
        else:
            raw_transport.write(_pack_plaintext_record(CONTENT_ALERT, payload, TLS_VERSION_1_2))
    except Exception:
        pass


async def _single_ech_handshake(
    *,
    raw_sock: socket.socket,
    resolved_ip: str,
    real_host: str,
    selected: SelectedEchConfig,
    no_tls_verify: bool,
    root_store: Optional[Store],
    alpn_protocols: Sequence[str],
    retried: bool,
) -> Tls13EchHandshakeResult:
    """Execute a single TLS 1.3 + RFC 9849 ECH handshake on *raw_sock*.

    On any error or ECH rejection, *raw_sock* and its transport are guaranteed closed/aborted
    with ZERO application data written.
    """
    loop = asyncio.get_running_loop()
    raw_proto = _RawTcpProtocol(loop)
    raw_transport: Optional[asyncio.Transport] = None
    client_hs_cipher: Optional[TlsRecordCipher] = None

    try:
        raw_transport, _ = await loop.create_connection(lambda: raw_proto, sock=raw_sock)
    except BaseException:
        try:
            raw_sock.close()
        except OSError:
            pass
        raise

    # raw_sock is now owned by raw_transport.
    try:
        # 1. HPKE SetupBaseS(pkR, "tls ech\0" || raw_ECHConfig)
        try:
            enc, hpke_sealer = setup_base_s(
                selected.kem_id,
                selected.kdf_id,
                selected.aead_id,
                selected.public_key,
                selected.hpke_info,
            )
        except HpkeError as exc:
            raise EchConfigError(f"HPKE setup failed for ECHConfig: {exc}") from exc

        inner_random = os.urandom(32)
        outer_random = os.urandom(32)
        session_id = os.urandom(32)

        initial_group = GROUP_X25519
        inner_sk, inner_pk = _generate_key_share(initial_group)
        outer_sk, outer_pk = _generate_key_share(initial_group)
        inner_key_shares: Dict[int, Union[x25519.X25519PrivateKey, ec.EllipticCurvePrivateKey]] = {
            initial_group: inner_sk
        }
        outer_key_shares: Dict[int, Union[x25519.X25519PrivateKey, ec.EllipticCurvePrivateKey]] = {
            initial_group: outer_sk
        }

        inner_ch1_msg, outer_ch1_msg, _ = build_ech_client_hello_pair(
            selected=selected,
            hpke_sealer=hpke_sealer,
            enc_for_outer=enc,
            real_host=real_host,
            inner_random=inner_random,
            outer_random=outer_random,
            session_id=session_id,
            inner_key_share=(initial_group, inner_pk),
            outer_key_share=(initial_group, outer_pk),
            alpn_protocols=alpn_protocols,
        )

        inner_transcript = bytearray(inner_ch1_msg)
        outer_transcript = bytearray(outer_ch1_msg)

        # Send ClientHelloOuter1 (legacy_record_version = 0x0301 for initial ClientHello)
        raw_transport.write(
            _pack_plaintext_record(CONTENT_HANDSHAKE, outer_ch1_msg, TLS_VERSION_1_0)
        )

        reader = _HandshakeReader(raw_proto)
        hrr_seen = False
        hrr_cipher_suite: Optional[int] = None
        hrr_ech_accepted = False
        expected_key_share_group = initial_group
        ccs_sent = False

        # 2. Receive ServerHello (with optional 1-round HelloRetryRequest)
        while True:
            hs_type, _hs_body, raw_msg = await reader.read_handshake_message()
            if hs_type != HS_SERVER_HELLO:
                _send_handshake_alert(raw_transport, None, ALERT_UNEXPECTED_MESSAGE)
                raise TlsError(f"expected ServerHello (0x02), got 0x{hs_type:02x}")

            sh = _parse_server_hello(raw_msg)
            if sh.session_id_echo != session_id:
                _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                raise TlsError("ServerHello legacy_session_id_echo mismatch")

            spec = CIPHER_SUITES.get(sh.cipher_suite)
            if spec is None:
                _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                raise TlsError(f"server selected unsupported TLS 1.3 cipher suite 0x{sh.cipher_suite:04x}")

            if sh.is_hrr:
                if hrr_seen:
                    _send_handshake_alert(raw_transport, None, ALERT_UNEXPECTED_MESSAGE)
                    raise TlsError("received second HelloRetryRequest")
                # RFC 8446 §5.1: no trailing handshake messages may be coalesced after HRR.
                if reader.hs_buf:
                    _send_handshake_alert(raw_transport, None, ALERT_UNEXPECTED_MESSAGE)
                    raise TlsError("unexpected trailing handshake bytes after HelloRetryRequest")
                # RFC 8446 §4.2 / RFC 9849 §7.2.1: reject unsolicited HRR extensions.
                for et in sh.extensions:
                    if et not in _ALLOWED_HRR_EXTENSIONS:
                        _send_handshake_alert(raw_transport, None, ALERT_UNSUPPORTED_EXTENSION)
                        raise TlsError(f"unsolicited HelloRetryRequest extension 0x{et:04x}")
                hrr_seen = True
                hrr_cipher_suite = sh.cipher_suite

                # Determine new key_share group and/or cookie requested by HRR
                req_group: Optional[int] = None
                ks_ext = sh.extensions.get(EXT_KEY_SHARE)
                if ks_ext is not None:
                    if len(ks_ext) != 2:
                        _send_handshake_alert(raw_transport, None, ALERT_DECODE_ERROR)
                        raise TlsError("invalid HRR key_share extension length")
                    (req_group,) = struct.unpack("!H", ks_ext)
                    if req_group not in SUPPORTED_GROUPS or req_group in inner_key_shares:
                        _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                        raise TlsError(f"invalid HRR selected_group 0x{req_group:04x}")

                cookie: Optional[bytes] = None
                cookie_ext = sh.extensions.get(EXT_COOKIE)
                if cookie_ext is not None:
                    if len(cookie_ext) < 2:
                        _send_handshake_alert(raw_transport, None, ALERT_DECODE_ERROR)
                        raise TlsError("truncated HRR cookie extension")
                    (clen,) = struct.unpack_from("!H", cookie_ext, 0)
                    if 2 + clen != len(cookie_ext) or clen == 0:
                        _send_handshake_alert(raw_transport, None, ALERT_DECODE_ERROR)
                        raise TlsError("invalid HRR cookie extension length")
                    cookie = cookie_ext[2:]

                if req_group is None and cookie is None:
                    _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                    raise TlsError("HelloRetryRequest requested neither new key_share nor cookie")

                # RFC 9849 §7.2.1: HRR ECH acceptance confirmation
                hrr_ech_ext = sh.extensions.get(EXT_ENCRYPTED_CLIENT_HELLO)
                if hrr_ech_ext is None:
                    hrr_ech_accepted = False
                else:
                    if len(hrr_ech_ext) != 8:
                        _send_handshake_alert(raw_transport, None, ALERT_DECODE_ERROR)
                        raise TlsError(f"invalid HRR ECH confirmation length: {len(hrr_ech_ext)}")
                    expected_hrr_conf = compute_hrr_ech_accept_confirmation(
                        spec,
                        inner_random,
                        inner_ch1_msg,
                        sh.raw_msg,
                        sh.ext_val_offsets[EXT_ENCRYPTED_CLIENT_HELLO],
                    )
                    hrr_ech_accepted = hmac.compare_digest(expected_hrr_conf, hrr_ech_ext)

                # RFC 8446 §4.4.1 transcript rollup with synthetic message_hash
                inner_msg_hash = (
                    bytes([HS_MESSAGE_HASH, 0x00, 0x00, spec.hash_len])
                    + hash_bytes(spec.hash_alg, bytes(inner_transcript))
                )
                outer_msg_hash = (
                    bytes([HS_MESSAGE_HASH, 0x00, 0x00, spec.hash_len])
                    + hash_bytes(spec.hash_alg, bytes(outer_transcript))
                )
                inner_transcript = bytearray(inner_msg_hash + sh.raw_msg)
                outer_transcript = bytearray(outer_msg_hash + sh.raw_msg)

                ch2_group = req_group if req_group is not None else initial_group
                expected_key_share_group = ch2_group
                if req_group is not None:
                    inner_sk2, inner_pk2 = _generate_key_share(req_group)
                    outer_sk2, outer_pk2 = _generate_key_share(req_group)
                    # RFC 8446 §4.2.8: CH2 offers ONLY the HRR-selected group; drop CH1's key share!
                    inner_key_shares = {req_group: inner_sk2}
                    outer_key_shares = {req_group: outer_sk2}
                else:
                    inner_pk2 = inner_pk
                    outer_pk2 = outer_pk

                # RFC 9849 §5.1: reuse SAME inner_random, SAME HPKE sealer (seq=1), enc = b""!
                outer_random2 = os.urandom(32)
                inner_ch2_msg, outer_ch2_msg, _ = build_ech_client_hello_pair(
                    selected=selected,
                    hpke_sealer=hpke_sealer,
                    enc_for_outer=b"",
                    real_host=real_host,
                    inner_random=inner_random,
                    outer_random=outer_random2,
                    session_id=session_id,
                    inner_key_share=(ch2_group, inner_pk2),
                    outer_key_share=(ch2_group, outer_pk2),
                    alpn_protocols=alpn_protocols,
                    cookie=cookie,
                )
                inner_transcript.extend(inner_ch2_msg)
                outer_transcript.extend(outer_ch2_msg)

                # Middlebox compat dummy CCS before CH2 (RFC 8446 Appendix D.4)
                if not ccs_sent:
                    raw_transport.write(
                        _pack_plaintext_record(CONTENT_CHANGE_CIPHER_SPEC, b"\x01", TLS_VERSION_1_2)
                    )
                    ccs_sent = True
                raw_transport.write(
                    _pack_plaintext_record(CONTENT_HANDSHAKE, outer_ch2_msg, TLS_VERSION_1_2)
                )
                continue

            # Normal ServerHello
            # RFC 8446 §5.1: ServerHello marks a key-change boundary; MUST NOT have trailing
            # plaintext handshake bytes coalesced in the same plaintext record!
            if reader.hs_buf:
                _send_handshake_alert(raw_transport, None, ALERT_UNEXPECTED_MESSAGE)
                raise TlsError("unexpected trailing plaintext handshake bytes after ServerHello")

            # RFC 8446 §4.2 / RFC 9849 §7.2: reject unsolicited extensions (including 0xFE0D!)
            for et in sh.extensions:
                if et not in _ALLOWED_SH_EXTENSIONS:
                    _send_handshake_alert(raw_transport, None, ALERT_UNSUPPORTED_EXTENSION)
                    raise TlsError(f"unsolicited ServerHello extension 0x{et:04x}")

            if hrr_seen and sh.cipher_suite != hrr_cipher_suite:
                _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                raise TlsError("ServerHello cipher suite changed after HelloRetryRequest")

            # Parse ServerHello key_share
            ks_ext = sh.extensions.get(EXT_KEY_SHARE)
            if ks_ext is None or len(ks_ext) < 4:
                _send_handshake_alert(raw_transport, None, ALERT_MISSING_EXTENSION)
                raise TlsError("ServerHello missing key_share extension")
            server_group, server_ks_len = struct.unpack_from("!HH", ks_ext, 0)
            if 4 + server_ks_len != len(ks_ext):
                _send_handshake_alert(raw_transport, None, ALERT_DECODE_ERROR)
                raise TlsError("ServerHello key_share length mismatch")
            if server_group != expected_key_share_group:
                _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                raise TlsError(
                    f"ServerHello key_share group 0x{server_group:04x} does not match "
                    f"offered group 0x{expected_key_share_group:04x}"
                )
            server_pub_bytes = ks_ext[4:]

            # RFC 9849 §7.2 ECH acceptance confirmation
            expected_conf = compute_ech_accept_confirmation(
                spec,
                inner_random,
                bytes(inner_transcript),
                sh.raw_msg,
            )
            sh_ech_confirmed = hmac.compare_digest(expected_conf, sh.random[24:32])

            if hrr_seen:
                if hrr_ech_accepted and not sh_ech_confirmed:
                    _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                    raise TlsError(
                        "server accepted ECH in HelloRetryRequest but failed ServerHello ECH confirmation"
                    )
                ech_accepted = hrr_ech_accepted and sh_ech_confirmed
            else:
                ech_accepted = sh_ech_confirmed

            if ech_accepted:
                transcript = inner_transcript + bytearray(sh.raw_msg)
                client_priv = inner_key_shares.get(server_group)
                expected_cert_host = real_host
            else:
                transcript = outer_transcript + bytearray(sh.raw_msg)
                client_priv = outer_key_shares.get(server_group)
                expected_cert_host = selected.public_name

            if client_priv is None:
                _send_handshake_alert(raw_transport, None, ALERT_ILLEGAL_PARAMETER)
                raise TlsError(f"server selected unoffered key_share group 0x{server_group:04x}")

            shared_secret = _compute_ecdhe_shared_secret(server_group, client_priv, server_pub_bytes)
            th_sh = hash_bytes(spec.hash_alg, bytes(transcript))
            _, client_hs_secret, server_hs_secret, master_secret = compute_handshake_secrets(
                spec, shared_secret, th_sh
            )

            client_hs_cipher = TlsRecordCipher(spec, client_hs_secret)
            server_hs_cipher = TlsRecordCipher(spec, server_hs_secret)
            reader.recv_cipher = server_hs_cipher
            break

        # 3. EncryptedExtensions (0x08)
        hs_type, ee_body, raw_ee = await reader.read_handshake_message()
        if hs_type != HS_ENCRYPTED_EXTENSIONS:
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_UNEXPECTED_MESSAGE)
            raise TlsError(f"expected EncryptedExtensions (0x08), got 0x{hs_type:02x}")
        transcript.extend(raw_ee)
        ee_exts = _parse_encrypted_extensions(ee_body)

        retry_configs_raw: Optional[bytes] = None
        if EXT_ENCRYPTED_CLIENT_HELLO in ee_exts:
            if ech_accepted:
                _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_UNSUPPORTED_EXTENSION)
                raise TlsError("server sent encrypted_client_hello in EncryptedExtensions after accepting ECH")
            retry_configs_raw = ee_exts[EXT_ENCRYPTED_CLIENT_HELLO]

        negotiated_alpn: Optional[str] = None
        if EXT_ALPN in ee_exts:
            if not alpn_protocols:
                _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_UNSUPPORTED_EXTENSION)
                raise TlsError("server sent unsolicited ALPN extension in EncryptedExtensions")
            alpn_raw = ee_exts[EXT_ALPN]
            if len(alpn_raw) < 3:
                _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_DECODE_ERROR)
                raise TlsError("malformed ALPN in EncryptedExtensions")
            (alpn_list_len,) = struct.unpack_from("!H", alpn_raw, 0)
            if 2 + alpn_list_len != len(alpn_raw) or alpn_list_len < 2:
                _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_DECODE_ERROR)
                raise TlsError("invalid ALPN list length in EncryptedExtensions")
            plen = alpn_raw[2]
            if 3 + plen != len(alpn_raw):
                _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_ILLEGAL_PARAMETER)
                raise TlsError("server ALPN contained multiple or truncated protocols")
            negotiated_alpn = alpn_raw[3 : 3 + plen].decode("ascii", errors="replace")
            if negotiated_alpn not in alpn_protocols:
                _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_ILLEGAL_PARAMETER)
                raise TlsError(f"server selected unoffered ALPN protocol {negotiated_alpn!r}")

        # 4. Optional CertificateRequest (0x0D) followed by Certificate (0x0B)
        send_empty_client_cert = False
        hs_type, hs_body, raw_hs = await reader.read_handshake_message()
        if hs_type == HS_CERTIFICATE_REQUEST:
            transcript.extend(raw_hs)
            send_empty_client_cert = True
            hs_type, hs_body, raw_hs = await reader.read_handshake_message()

        if hs_type != HS_CERTIFICATE:
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_UNEXPECTED_MESSAGE)
            raise TlsError(f"expected Certificate (0x0B), got 0x{hs_type:02x}")
        transcript.extend(raw_hs)
        certs = _parse_certificate_message(hs_body)

        # 5. CertificateVerify (0x0F)
        hs_type, cv_body, raw_cv = await reader.read_handshake_message()
        if hs_type != HS_CERTIFICATE_VERIFY:
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_UNEXPECTED_MESSAGE)
            raise TlsError(f"expected CertificateVerify (0x0F), got 0x{hs_type:02x}")
        th_before_cv = hash_bytes(spec.hash_alg, bytes(transcript))
        try:
            verify_certificate_verify(certs[0], th_before_cv, cv_body)
        except Exception:
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_DECRYPT_ERROR)
            raise
        transcript.extend(raw_cv)

        # Strict RFC 5280 X.509 verification against expected_cert_host
        # (real_host if ECH accepted; selected.public_name if ECH rejected!)
        if not no_tls_verify:
            assert root_store is not None
            try:
                verify_server_certificate_chain(certs, expected_cert_host, store=root_store)
            except ssl.SSLCertVerificationError:
                _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_BAD_CERTIFICATE)
                raise

        # 6. Server Finished (0x14)
        hs_type, sf_body, raw_sf = await reader.read_handshake_message()
        if hs_type != HS_FINISHED:
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_UNEXPECTED_MESSAGE)
            raise TlsError(f"expected Server Finished (0x14), got 0x{hs_type:02x}")
        th_before_sf = hash_bytes(spec.hash_alg, bytes(transcript))
        expected_sf = derive_finished_verify_data(spec.hash_alg, server_hs_secret, th_before_sf)
        if len(sf_body) != spec.hash_len or not hmac.compare_digest(sf_body, expected_sf):
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_DECRYPT_ERROR)
            raise TlsError("server Finished MAC verification failed (decrypt_error)")
        transcript.extend(raw_sf)

        # RFC 8446 §5.1: handshake messages MUST NOT span key changes.
        if reader.hs_buf:
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_UNEXPECTED_MESSAGE)
            raise TlsError("unexpected trailing handshake bytes across key change")

        # 7. RFC 9849 §7.2: If ECH was rejected, outer cert + CertificateVerify + Server Finished
        # are NOW strictly authenticated. Send fatal ech_required (0x79), close socket with ZERO
        # application data sent, and surface verified retry_configs to caller!
        if not ech_accepted:
            _send_handshake_alert(raw_transport, client_hs_cipher, ALERT_ECH_REQUIRED)
            raw_transport.close()
            raw_transport = None  # closed cleanly
            raise EchRejectedError(
                f"server rejected ECH for {real_host!r} (authenticated outer server {selected.public_name!r})",
                retry_configs=retry_configs_raw,
                public_name=selected.public_name,
            )

        # 8. Derive application traffic keys from transcript through Server Finished
        th_after_sf = hash_bytes(spec.hash_alg, bytes(transcript))
        client_app_secret, server_app_secret = compute_app_secrets(spec, master_secret, th_after_sf)

        # 9. Send optional dummy CCS + optional empty Client Certificate + Client Finished
        if not ccs_sent:
            raw_transport.write(
                _pack_plaintext_record(CONTENT_CHANGE_CIPHER_SPEC, b"\x01", TLS_VERSION_1_2)
            )
            ccs_sent = True

        if send_empty_client_cert:
            empty_cert_msg = _pack_handshake(HS_CERTIFICATE, b"\x00\x00\x00\x00")
            transcript.extend(empty_cert_msg)
            raw_transport.write(client_hs_cipher.encrypt_record(CONTENT_HANDSHAKE, empty_cert_msg))

        client_verify_data = derive_finished_verify_data(
            spec.hash_alg, client_hs_secret, hash_bytes(spec.hash_alg, bytes(transcript))
        )
        client_finished_msg = _pack_handshake(HS_FINISHED, client_verify_data)
        raw_transport.write(client_hs_cipher.encrypt_record(CONTENT_HANDSHAKE, client_finished_msg))

        # 10. Switch to application traffic keys and wrap in Tls13EchTransport
        tls_transport = Tls13EchTransport(
            loop=loop,
            raw_transport=raw_transport,
            raw_protocol=raw_proto,
            send_cipher=TlsRecordCipher(spec, client_app_secret),
            recv_cipher=TlsRecordCipher(spec, server_app_secret),
            cipher_spec=spec,
            outer_sni=selected.public_name,
            real_host=real_host,
            alpn=negotiated_alpn,
            peer_cert=certs[0],
        )
        leftover = raw_proto.attach_tls_transport(tls_transport)
        # Keep leftover on transport for flushing right after upper protocol attaches
        tls_transport._recv_buf.extend(leftover)
        # Ownership of raw_transport transferred to tls_transport
        raw_transport = None

        return Tls13EchHandshakeResult(
            transport=tls_transport,
            ech_status="accepted",
            outer_sni=selected.public_name,
            resolved_ip=resolved_ip,
            retried=retried,
            cipher_suite=spec.name,
            alpn=negotiated_alpn,
            tls_version="TLSv1.3",
        )
    except BaseException:
        if raw_transport is not None:
            raw_transport.abort()
        raise


async def connect_tls13_ech(
    *,
    sock_factory: Callable[[], Awaitable[Tuple[socket.socket, str]]],
    real_host: str,
    ech_config_list: bytes,
    protocol: Optional[asyncio.BaseProtocol] = None,
    no_tls_verify: bool = False,
    base_ssl_context: Optional[ssl.SSLContext] = None,
    handshake_timeout: float = 10.0,
    alpn_protocols: Sequence[str] = ("http/1.1",),
    call_connection_made: bool = False,
    on_warn: Optional[Callable[[str], None]] = None,
    initial_sock: Optional[Tuple[socket.socket, str]] = None,
) -> Tls13EchHandshakeResult:
    """Connect and complete a TRUE TLS 1.3 + RFC 9849 ECH handshake with 1-shot ``retry_configs`` retry.

    Guarantees:
    - All sockets/transports are closed cleanly on error or cancellation (zero fd/task leaks).
    - On ECH rejection, strictly authenticates the outer server cert for ``public_name``,
      ``CertificateVerify``, and server ``Finished``, sends fatal ``ech_required (0x79)``,
      closes the initial TCP socket with ZERO application bytes written, and retries at most once
      on a fresh TCP socket using the server's verified ``retry_configs``.
    """
    current_ech_bytes = ech_config_list
    retried = False
    pending_initial = initial_sock

    root_store: Optional[Store] = None
    if not no_tls_verify:
        root_store = load_root_store(base_ssl_context)

    try:
        while True:
            selected = select_ech_config(current_ech_bytes)
            if selected is None:
                if pending_initial is not None:
                    try:
                        pending_initial[0].close()
                    except OSError:
                        pass
                    pending_initial = None
                raise EchConfigError(
                    "ECHConfigList is invalid or contains no compatible HPKE cipher suite"
                )

            if pending_initial is not None:
                raw_sock, resolved_ip = pending_initial
                pending_initial = None
            else:
                raw_sock, resolved_ip = await sock_factory()

            try:
                result = await asyncio.wait_for(
                    _single_ech_handshake(
                        raw_sock=raw_sock,
                        resolved_ip=resolved_ip,
                        real_host=real_host,
                        selected=selected,
                        no_tls_verify=no_tls_verify,
                        root_store=root_store,
                        alpn_protocols=alpn_protocols,
                        retried=retried,
                    ),
                    timeout=handshake_timeout,
                )
            except asyncio.TimeoutError as exc:
                raise TlsError(
                    f"TLS 1.3 ECH handshake to {resolved_ip} timed out after {handshake_timeout:.1f}s"
                ) from exc
            except EchRejectedError as exc:
                if not retried and exc.retry_configs:
                    if select_ech_config(exc.retry_configs) is not None:
                        warn_msg = (
                            "Server rejected initial ECH config and supplied retry_configs; "
                            "retrying ECH once."
                        )
                        logger.warning("%s", warn_msg)
                        if on_warn is not None:
                            try:
                                on_warn(warn_msg)
                            except Exception:
                                pass
                        current_ech_bytes = exc.retry_configs
                        retried = True
                        continue
                if retried:
                    raise EchRejectedError(
                        "server rejected ECH even after RFC 9849 retry_configs retry",
                        retry_configs=exc.retry_configs,
                        public_name=exc.public_name,
                    ) from exc
                raise EchRejectedError(
                    "server rejected ECH without usable retry_configs",
                    retry_configs=exc.retry_configs,
                    public_name=exc.public_name,
                ) from exc

            # Handshake succeeded with ECH accepted! Attach upper protocol if requested.
            if protocol is not None:
                result.transport.set_protocol(protocol)
                if call_connection_made:
                    protocol.connection_made(result.transport)
                # Drain any buffered post-handshake records (e.g., NewSessionTicket)
                buffered = bytes(result.transport._recv_buf)
                result.transport._recv_buf.clear()
                result.transport.flush_initial_bytes(buffered)
            return result
    except BaseException:
        if pending_initial is not None:
            try:
                pending_initial[0].close()
            except OSError:
                pass
            pending_initial = None
        raise
