"""RFC 9180 Base-mode HPKE and RFC 9849 ECHConfigList parser/selector over ``cryptography``.

Supports:
- KEMs: ``DHKEM(X25519, HKDF-SHA256)`` (0x0020), ``DHKEM(P-256, HKDF-SHA256)`` (0x0010)
- KDF: ``HKDF-SHA256`` (0x0001)
- AEADs: ``AES-128-GCM`` (0x0001), ``AES-256-GCM`` (0x0002), ``ChaCha20Poly1305`` (0x0003)
"""

from __future__ import annotations

import base64
import binascii
import hmac
import re
import struct
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import TunnelError

# RFC 9849 ECH codepoints
ECH_VERSION_V18 = 0xFE0D

# RFC 9180 HPKE identifiers
MODE_BASE = 0x00

KEM_DHKEM_P256_HKDF_SHA256 = 0x0010
KEM_DHKEM_X25519_HKDF_SHA256 = 0x0020

KDF_HKDF_SHA256 = 0x0001

AEAD_AES_128_GCM = 0x0001
AEAD_AES_256_GCM = 0x0002
AEAD_CHACHA20_POLY1305 = 0x0003
AEAD_EXPORT_ONLY = 0xFFFF

NH_SHA256 = 32
NONCE_LEN = 12
TAG_LEN = 16
MAX_SEQ = (1 << 64) - 1

SUPPORTED_KEMS: Tuple[int, ...] = (
    KEM_DHKEM_X25519_HKDF_SHA256,
    KEM_DHKEM_P256_HKDF_SHA256,
)

SUPPORTED_KDFS: Tuple[int, ...] = (KDF_HKDF_SHA256,)

SUPPORTED_AEADS: Tuple[int, ...] = (
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
    AEAD_CHACHA20_POLY1305,
)

SUPPORTED_SUITES: Tuple[Tuple[int, int, int], ...] = (
    (KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM),
    (KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM),
    (KEM_DHKEM_X25519_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20_POLY1305),
    (KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_128_GCM),
    (KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_AES_256_GCM),
    (KEM_DHKEM_P256_HKDF_SHA256, KDF_HKDF_SHA256, AEAD_CHACHA20_POLY1305),
)

_AEAD_KEY_LEN = {
    AEAD_AES_128_GCM: 16,
    AEAD_AES_256_GCM: 32,
    AEAD_CHACHA20_POLY1305: 32,
}

# P-256 curve order n (RFC 9180 §7.1.3 / FIPS 186-4)
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Complete set of Curve25519 low-order u-coordinates with bit 255 cleared (covers all 14 encodings:
# 0, 1, two order-8 points, p-1, p, p+1 with MSB 0 or 1; RFC 7748 §6.1 / RFC 9180 §7.1.4).
_X25519_LOW_ORDER_MASKED = frozenset(
    bytes.fromhex(h)
    for h in (
        "0000000000000000000000000000000000000000000000000000000000000000",  # 0
        "0100000000000000000000000000000000000000000000000000000000000000",  # 1
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",  # order-8
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",  # order-8
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # p - 1
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # p
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # p + 1
    )
)

_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class HpkeError(TunnelError, ValueError):
    """Raised on HPKE cryptographic, key validation, sequence overflow, or ECHConfig errors."""


@dataclass(frozen=True)
class EchConfig:
    """Parsed RFC 9849 ECHConfig (version ``0xFE0D``)."""

    version: int
    config_id: int
    kem_id: int
    public_key: bytes
    cipher_suites: Tuple[Tuple[int, int], ...]  # (kdf_id, aead_id)
    maximum_name_length: int
    public_name: str
    extensions: Tuple[Tuple[int, bytes], ...]
    raw_config: bytes  # exact wire bytes: version(2) || length(2) || contents


@dataclass(frozen=True)
class SelectedEchConfig:
    """Validated ECHConfig paired with a concrete supported HPKE suite."""

    config: EchConfig
    kdf_id: int
    aead_id: int

    @property
    def config_id(self) -> int:
        return self.config.config_id

    @property
    def kem_id(self) -> int:
        return self.config.kem_id

    @property
    def public_key(self) -> bytes:
        return self.config.public_key

    @property
    def maximum_name_length(self) -> int:
        return self.config.maximum_name_length

    @property
    def public_name(self) -> str:
        return self.config.public_name

    @property
    def raw_config(self) -> bytes:
        return self.config.raw_config

    @property
    def hpke_info(self) -> bytes:
        """RFC 9849 §6.1: ``"tls ech\\0" || raw_ECHConfig``."""
        return b"tls ech\x00" + self.config.raw_config


def kem_suite_id(kem_id: int) -> bytes:
    """RFC 9180 §4.1 ``suite_id = concat("KEM", I2OSP(kem_id, 2))``."""
    return b"KEM" + struct.pack("!H", kem_id)


def hpke_suite_id(kem_id: int, kdf_id: int, aead_id: int) -> bytes:
    """RFC 9180 §5.1 ``suite_id = concat("HPKE", I2OSP(kem_id, 2), I2OSP(kdf_id, 2), I2OSP(aead_id, 2))``."""
    return b"HPKE" + struct.pack("!HHH", kem_id, kdf_id, aead_id)


def labeled_extract(suite_id: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    """RFC 9180 §4 ``LabeledExtract(salt, label, ikm)`` using HKDF-SHA256."""
    key = salt if salt else (b"\x00" * NH_SHA256)
    mac = crypto_hmac.HMAC(key, hashes.SHA256())
    mac.update(b"HPKE-v1")
    mac.update(suite_id)
    mac.update(label)
    mac.update(ikm)
    return mac.finalize()


def labeled_expand(
    suite_id: bytes,
    prk: bytes,
    label: bytes,
    info: bytes,
    length: int,
) -> bytes:
    """RFC 9180 §4 ``LabeledExpand(prk, label, info, L)`` using HKDF-SHA256."""
    if length < 0 or length > 255 * NH_SHA256:
        raise HpkeError(f"invalid HKDF-Expand output length: {length}")
    if length == 0:
        return b""
    labeled_info = struct.pack("!H", length) + b"HPKE-v1" + suite_id + label + info
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=labeled_info,
    ).derive(prk)


def _extract_and_expand(kem_id: int, dh: bytes, kem_context: bytes) -> bytes:
    """RFC 9180 §4.1 ``ExtractAndExpand(dh, kem_context)``."""
    sid = kem_suite_id(kem_id)
    eae_prk = labeled_extract(sid, b"", b"eae_prk", dh)
    return labeled_expand(sid, eae_prk, b"shared_secret", kem_context, NH_SHA256)


def validate_kem_public_key(kem_id: int, pub_bytes: bytes) -> None:
    """Strictly validate a serialized KEM public key (X25519 32B or uncompressed P-256 65B)."""
    if kem_id == KEM_DHKEM_X25519_HKDF_SHA256:
        if len(pub_bytes) != 32:
            raise HpkeError(f"invalid X25519 public key length: {len(pub_bytes)} (expected 32)")
        masked = bytearray(pub_bytes)
        masked[31] &= 0x7F
        if bytes(masked) in _X25519_LOW_ORDER_MASKED:
            raise HpkeError("rejected low-order X25519 public key")
        try:
            x25519.X25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as exc:
            raise HpkeError(f"invalid X25519 public key: {exc}") from exc
        return

    if kem_id == KEM_DHKEM_P256_HKDF_SHA256:
        if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
            raise HpkeError(
                f"invalid P-256 public key encoding: length={len(pub_bytes)}, "
                f"prefix=0x{pub_bytes[0]:02x}" if pub_bytes else "empty P-256 public key"
            )
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub_bytes)
        except Exception as exc:
            raise HpkeError(f"invalid or off-curve P-256 public key: {exc}") from exc
        return

    raise HpkeError(f"unsupported HPKE KEM ID: 0x{kem_id:04x}")


def _dh_x25519(sk: x25519.X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    validate_kem_public_key(KEM_DHKEM_X25519_HKDF_SHA256, peer_pub_bytes)
    peer_pk = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    try:
        dh = sk.exchange(peer_pk)
    except Exception as exc:
        raise HpkeError(f"X25519 key agreement failed (low-order or invalid peer key): {exc}") from exc
    if len(dh) != 32 or hmac.compare_digest(dh, b"\x00" * 32):
        raise HpkeError("X25519 key agreement produced all-zero shared secret")
    return dh


def _dh_p256(sk: ec.EllipticCurvePrivateKey, peer_pub_bytes: bytes) -> bytes:
    validate_kem_public_key(KEM_DHKEM_P256_HKDF_SHA256, peer_pub_bytes)
    peer_pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_pub_bytes)
    try:
        dh = sk.exchange(ec.ECDH(), peer_pk)
    except Exception as exc:
        raise HpkeError(f"P-256 ECDH key agreement failed: {exc}") from exc
    if len(dh) != 32:
        raise HpkeError(f"unexpected P-256 ECDH shared secret length: {len(dh)}")
    return dh


def _load_ephemeral_private_key(
    kem_id: int,
    sk_bytes: Optional[bytes],
) -> Union[x25519.X25519PrivateKey, ec.EllipticCurvePrivateKey]:
    if kem_id == KEM_DHKEM_X25519_HKDF_SHA256:
        if sk_bytes is None:
            return x25519.X25519PrivateKey.generate()
        if len(sk_bytes) != 32:
            raise HpkeError(f"invalid X25519 private key length: {len(sk_bytes)}")
        return x25519.X25519PrivateKey.from_private_bytes(sk_bytes)

    if kem_id == KEM_DHKEM_P256_HKDF_SHA256:
        if sk_bytes is None:
            return ec.generate_private_key(ec.SECP256R1())
        if len(sk_bytes) != 32:
            raise HpkeError(f"invalid P-256 private scalar length: {len(sk_bytes)}")
        scalar = int.from_bytes(sk_bytes, "big")
        if scalar <= 0 or scalar >= _P256_ORDER:
            raise HpkeError("P-256 private scalar out of range [1, n-1]")
        return ec.derive_private_key(scalar, ec.SECP256R1())

    raise HpkeError(f"unsupported HPKE KEM ID: 0x{kem_id:04x}")


def serialize_kem_public_key(
    kem_id: int,
    sk: Union[x25519.X25519PrivateKey, ec.EllipticCurvePrivateKey],
) -> bytes:
    """Serialize the public key corresponding to *sk* in RFC 9180 KEM wire format."""
    if kem_id == KEM_DHKEM_X25519_HKDF_SHA256:
        assert isinstance(sk, x25519.X25519PrivateKey)
        return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    if kem_id == KEM_DHKEM_P256_HKDF_SHA256:
        assert isinstance(sk, ec.EllipticCurvePrivateKey)
        return sk.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    raise HpkeError(f"unsupported HPKE KEM ID: 0x{kem_id:04x}")


def encap(
    kem_id: int,
    pk_r: bytes,
    *,
    ephemeral_sk_bytes: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """RFC 9180 §4.1 ``Encap(pkR)`` -> ``(shared_secret, enc)``."""
    sk_e = _load_ephemeral_private_key(kem_id, ephemeral_sk_bytes)
    enc = serialize_kem_public_key(kem_id, sk_e)

    if kem_id == KEM_DHKEM_X25519_HKDF_SHA256:
        assert isinstance(sk_e, x25519.X25519PrivateKey)
        dh = _dh_x25519(sk_e, pk_r)
    elif kem_id == KEM_DHKEM_P256_HKDF_SHA256:
        assert isinstance(sk_e, ec.EllipticCurvePrivateKey)
        dh = _dh_p256(sk_e, pk_r)
    else:
        raise HpkeError(f"unsupported HPKE KEM ID: 0x{kem_id:04x}")

    kem_context = enc + pk_r
    shared_secret = _extract_and_expand(kem_id, dh, kem_context)
    return shared_secret, enc


def decap(
    kem_id: int,
    enc: bytes,
    sk_r_bytes: bytes,
) -> bytes:
    """RFC 9180 §4.1 ``Decap(enc, skR)`` -> ``shared_secret``."""
    sk_r = _load_ephemeral_private_key(kem_id, sk_r_bytes)
    pk_r = serialize_kem_public_key(kem_id, sk_r)

    if kem_id == KEM_DHKEM_X25519_HKDF_SHA256:
        assert isinstance(sk_r, x25519.X25519PrivateKey)
        dh = _dh_x25519(sk_r, enc)
    elif kem_id == KEM_DHKEM_P256_HKDF_SHA256:
        assert isinstance(sk_r, ec.EllipticCurvePrivateKey)
        dh = _dh_p256(sk_r, enc)
    else:
        raise HpkeError(f"unsupported HPKE KEM ID: 0x{kem_id:04x}")

    kem_context = enc + pk_r
    return _extract_and_expand(kem_id, dh, kem_context)


def _build_aead(aead_id: int, key: bytes) -> Union[AESGCM, ChaCha20Poly1305]:
    if aead_id in (AEAD_AES_128_GCM, AEAD_AES_256_GCM):
        return AESGCM(key)
    if aead_id == AEAD_CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)
    raise HpkeError(f"unsupported HPKE AEAD ID: 0x{aead_id:04x}")


def _key_schedule_base(
    kem_id: int,
    kdf_id: int,
    aead_id: int,
    shared_secret: bytes,
    info: bytes,
) -> Tuple[bytes, bytes, bytes]:
    """RFC 9180 §5.1 ``KeySchedule(mode_base, shared_secret, info, "", "")`` -> ``(key, base_nonce, exporter_secret)``."""
    if (kem_id, kdf_id, aead_id) not in SUPPORTED_SUITES:
        raise HpkeError(
            f"unsupported HPKE cipher suite: kem=0x{kem_id:04x} kdf=0x{kdf_id:04x} aead=0x{aead_id:04x}"
        )
    sid = hpke_suite_id(kem_id, kdf_id, aead_id)
    psk_id_hash = labeled_extract(sid, b"", b"psk_id_hash", b"")
    info_hash = labeled_extract(sid, b"", b"info_hash", info)
    ks_context = bytes([MODE_BASE]) + psk_id_hash + info_hash

    secret = labeled_extract(sid, shared_secret, b"secret", b"")
    key_len = _AEAD_KEY_LEN[aead_id]
    key = labeled_expand(sid, secret, b"key", ks_context, key_len)
    base_nonce = labeled_expand(sid, secret, b"base_nonce", ks_context, NONCE_LEN)
    exporter_secret = labeled_expand(sid, secret, b"exp", ks_context, NH_SHA256)
    return key, base_nonce, exporter_secret


class HpkeContext:
    """Base HPKE encryption/decryption context (RFC 9180 §5.2)."""

    def __init__(
        self,
        *,
        aead_id: int,
        key: bytes,
        base_nonce: bytes,
        exporter_secret: bytes,
        max_seq: int = MAX_SEQ,
    ) -> None:
        if len(base_nonce) != NONCE_LEN:
            raise HpkeError(f"invalid base_nonce length: {len(base_nonce)}")
        self._aead_id = aead_id
        self._key = key
        self._base_nonce = base_nonce
        self._exporter_secret = exporter_secret
        self._aead = _build_aead(aead_id, key)
        self._seq = 0
        self._max_seq = max_seq

    @property
    def key(self) -> bytes:
        return self._key

    @property
    def base_nonce(self) -> bytes:
        return self._base_nonce

    @property
    def exporter_secret(self) -> bytes:
        return self._exporter_secret

    @property
    def seq(self) -> int:
        return self._seq

    def _compute_nonce(self, seq: int) -> bytes:
        seq_bytes = seq.to_bytes(NONCE_LEN, "big")
        return bytes(a ^ b for a, b in zip(self._base_nonce, seq_bytes))


class HpkeSealer(HpkeContext):
    """RFC 9180 Base-mode sender context (``ContextS``)."""

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        if self._seq >= self._max_seq:
            raise HpkeError("HPKE sequence number overflow")
        nonce = self._compute_nonce(self._seq)
        ciphertext = self._aead.encrypt(nonce, plaintext, aad)
        self._seq += 1
        return ciphertext


class HpkeOpener(HpkeContext):
    """RFC 9180 Base-mode recipient context (``ContextR``)."""

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        if self._seq >= self._max_seq:
            raise HpkeError("HPKE sequence number overflow")
        nonce = self._compute_nonce(self._seq)
        try:
            plaintext = self._aead.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise HpkeError("HPKE AEAD authentication failed") from exc
        self._seq += 1
        return plaintext


def setup_base_s(
    kem_id: int,
    kdf_id: int,
    aead_id: int,
    pk_r: bytes,
    info: bytes,
    *,
    ephemeral_sk_bytes: Optional[bytes] = None,
) -> Tuple[bytes, HpkeSealer]:
    """RFC 9180 §5.1.1 ``SetupBaseS(pkR, info)`` -> ``(enc, sealer)``."""
    if (kem_id, kdf_id, aead_id) not in SUPPORTED_SUITES:
        raise HpkeError(
            f"unsupported HPKE cipher suite: kem=0x{kem_id:04x} kdf=0x{kdf_id:04x} aead=0x{aead_id:04x}"
        )
    shared_secret, enc = encap(kem_id, pk_r, ephemeral_sk_bytes=ephemeral_sk_bytes)
    key, base_nonce, exporter_secret = _key_schedule_base(
        kem_id, kdf_id, aead_id, shared_secret, info
    )
    sealer = HpkeSealer(
        aead_id=aead_id,
        key=key,
        base_nonce=base_nonce,
        exporter_secret=exporter_secret,
    )
    return enc, sealer


def setup_base_r(
    kem_id: int,
    kdf_id: int,
    aead_id: int,
    enc: bytes,
    sk_r_bytes: bytes,
    info: bytes,
) -> HpkeOpener:
    """RFC 9180 §5.1.1 ``SetupBaseR(enc, skR, info)`` -> ``opener``."""
    if (kem_id, kdf_id, aead_id) not in SUPPORTED_SUITES:
        raise HpkeError(
            f"unsupported HPKE cipher suite: kem=0x{kem_id:04x} kdf=0x{kdf_id:04x} aead=0x{aead_id:04x}"
        )
    shared_secret = decap(kem_id, enc, sk_r_bytes)
    key, base_nonce, exporter_secret = _key_schedule_base(
        kem_id, kdf_id, aead_id, shared_secret, info
    )
    return HpkeOpener(
        aead_id=aead_id,
        key=key,
        base_nonce=base_nonce,
        exporter_secret=exporter_secret,
    )


def seal_base(
    kem_id: int,
    kdf_id: int,
    aead_id: int,
    pk_r: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
) -> Tuple[bytes, bytes]:
    """Single-shot RFC 9180 §6.1 ``SealBase(pkR, info, aad, pt)`` -> ``(enc, ct)``."""
    enc, sealer = setup_base_s(kem_id, kdf_id, aead_id, pk_r, info)
    return enc, sealer.seal(aad, plaintext)


# ---------------------------------------------------------------------------
# RFC 9849 ECHConfigList parsing, validation, and encoding
# ---------------------------------------------------------------------------


def _is_valid_ech_public_name(name: str) -> bool:
    """Validate RFC 9849 §4 ``public_name`` (non-empty LDH DNS hostname, no trailing dot)."""
    if not name or len(name) > 255 or name.startswith(".") or name.endswith("."):
        return False
    labels = name.split(".")
    for label in labels:
        if not _DNS_LABEL_RE.match(label):
            return False
    # Last label must not be all digits (reject IPv4 literals as public_name).
    if labels[-1].isdigit():
        return False
    return True


def decode_ech_config_list_base64(value: str) -> bytes:
    """Strictly decode a base64-encoded RFC 9849 ``ECHConfigList`` string."""
    cleaned = "".join(value.split())
    if not cleaned:
        raise HpkeError("ECHConfigList base64 string must not be empty")
    try:
        raw = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HpkeError(f"invalid base64 ECHConfigList: {exc}") from exc
    if not raw:
        raise HpkeError("decoded ECHConfigList is empty")
    return raw


def parse_ech_config_list(data: bytes) -> List[EchConfig]:
    """Parse an RFC 9849 ``ECHConfigList`` wire payload into supported ``0xFE0D`` configs.

    Skips configs with unsupported versions or unknown mandatory extensions per RFC 9849 §4.2,
    while rejecting malformed list framing, duplicate extension types, or truncated records.
    """
    if len(data) < 2:
        raise HpkeError("ECHConfigList too short")
    (list_len,) = struct.unpack_from("!H", data, 0)
    if list_len == 0 or 2 + list_len != len(data):
        raise HpkeError(
            f"invalid ECHConfigList length: declared={list_len}, actual={len(data) - 2}"
        )

    configs: List[EchConfig] = []
    pos = 2
    end = len(data)

    while pos < end:
        if pos + 4 > end:
            raise HpkeError("truncated ECHConfig header")
        cfg_start = pos
        version, cfg_len = struct.unpack_from("!HH", data, pos)
        pos += 4
        if pos + cfg_len > end:
            raise HpkeError("truncated ECHConfig body")
        contents = data[pos : pos + cfg_len]
        raw_config = data[cfg_start : pos + cfg_len]
        pos += cfg_len

        if version != ECH_VERSION_V18:
            # RFC 9849 §4.2: ignore unknown ECHConfig versions.
            continue

        cfg = _parse_ech_config_contents(version, contents, raw_config)
        if cfg is not None:
            configs.append(cfg)

    return configs


def _parse_ech_config_contents(
    version: int,
    contents: bytes,
    raw_config: bytes,
) -> Optional[EchConfig]:
    """Parse ``ECHConfigContents``; return ``None`` if config has unknown mandatory extensions."""
    cpos = 0
    clen = len(contents)

    # config_id (1) + kem_id (2) + pk_len (2)
    if cpos + 5 > clen:
        raise HpkeError("truncated ECHConfigContents header")
    config_id, kem_id, pk_len = struct.unpack_from("!BHH", contents, cpos)
    cpos += 5
    if pk_len == 0 or cpos + pk_len > clen:
        raise HpkeError("invalid ECHConfigContents public_key length")
    public_key = contents[cpos : cpos + pk_len]
    cpos += pk_len

    # cipher_suites<4..2^16-4>
    if cpos + 2 > clen:
        raise HpkeError("truncated ECHConfigContents cipher_suites length")
    (cs_len,) = struct.unpack_from("!H", contents, cpos)
    cpos += 2
    if cs_len < 4 or cs_len % 4 != 0 or cpos + cs_len > clen:
        raise HpkeError("invalid ECHConfigContents cipher_suites length")
    cipher_suites: List[Tuple[int, int]] = []
    cs_end = cpos + cs_len
    while cpos < cs_end:
        kdf_id, aead_id = struct.unpack_from("!HH", contents, cpos)
        cpos += 4
        cipher_suites.append((kdf_id, aead_id))

    # maximum_name_length (1) + public_name_len (1)
    if cpos + 2 > clen:
        raise HpkeError("truncated ECHConfigContents public_name header")
    maximum_name_length = contents[cpos]
    pub_len = contents[cpos + 1]
    cpos += 2
    if pub_len == 0 or cpos + pub_len > clen:
        raise HpkeError("invalid ECHConfigContents public_name length")
    try:
        public_name = contents[cpos : cpos + pub_len].decode("ascii")
    except UnicodeDecodeError as exc:
        raise HpkeError("non-ASCII ECHConfigContents public_name") from exc
    cpos += pub_len

    # extensions<0..2^16-1>
    if cpos + 2 > clen:
        raise HpkeError("truncated ECHConfigContents extensions length")
    (ext_len,) = struct.unpack_from("!H", contents, cpos)
    cpos += 2
    if cpos + ext_len != clen:
        raise HpkeError("ECHConfigContents extensions length mismatch / trailing data")

    extensions: List[Tuple[int, bytes]] = []
    seen_ext_types = set()
    has_unknown_mandatory = False
    while cpos < clen:
        if cpos + 4 > clen:
            raise HpkeError("truncated ECHConfigExtension header")
        ext_type, edata_len = struct.unpack_from("!HH", contents, cpos)
        cpos += 4
        if cpos + edata_len > clen:
            raise HpkeError("truncated ECHConfigExtension payload")
        edata = contents[cpos : cpos + edata_len]
        cpos += edata_len
        if ext_type in seen_ext_types:
            raise HpkeError(f"duplicate ECHConfigExtension type 0x{ext_type:04x}")
        seen_ext_types.add(ext_type)
        if ext_type & 0x8000:
            has_unknown_mandatory = True
        extensions.append((ext_type, edata))

    if has_unknown_mandatory:
        # RFC 9849 §4.2: clients MUST ignore ECHConfigs containing unrecognized mandatory extensions.
        return None

    if not _is_valid_ech_public_name(public_name):
        return None

    return EchConfig(
        version=version,
        config_id=config_id,
        kem_id=kem_id,
        public_key=public_key,
        cipher_suites=tuple(cipher_suites),
        maximum_name_length=maximum_name_length,
        public_name=public_name,
        extensions=tuple(extensions),
        raw_config=raw_config,
    )


def select_ech_config(ech_config_list: bytes) -> Optional[SelectedEchConfig]:
    """Select the first ECHConfig & HPKE suite compatible with our supported suites."""
    try:
        configs = parse_ech_config_list(ech_config_list)
    except HpkeError:
        return None

    for cfg in configs:
        if cfg.kem_id not in SUPPORTED_KEMS:
            continue
        try:
            validate_kem_public_key(cfg.kem_id, cfg.public_key)
        except HpkeError:
            continue
        for kdf_id, aead_id in cfg.cipher_suites:
            if aead_id == AEAD_EXPORT_ONLY:
                continue
            if (cfg.kem_id, kdf_id, aead_id) in SUPPORTED_SUITES:
                return SelectedEchConfig(config=cfg, kdf_id=kdf_id, aead_id=aead_id)
    return None


def select_ech_public_name(ech_config_list: bytes) -> Optional[str]:
    """Return the outer ``public_name`` of the first compatible ECHConfig, if any."""
    selected = select_ech_config(ech_config_list)
    return selected.public_name if selected is not None else None


def encode_ech_config(
    *,
    config_id: int,
    kem_id: int,
    public_key: bytes,
    cipher_suites: Sequence[Tuple[int, int]],
    maximum_name_length: int = 64,
    public_name: str = "cloudflare-ech.com",
    extensions: Sequence[Tuple[int, bytes]] = (),
    version: int = ECH_VERSION_V18,
) -> bytes:
    """Encode a single RFC 9849 ``ECHConfig`` (``version || length || contents``)."""
    cs_bytes = b"".join(struct.pack("!HH", kdf, aead) for kdf, aead in cipher_suites)
    pub_bytes = public_name.encode("ascii")
    ext_bytes = b"".join(
        struct.pack("!HH", etype, len(edata)) + edata for etype, edata in extensions
    )
    contents = (
        struct.pack("!BH", config_id & 0xFF, kem_id)
        + struct.pack("!H", len(public_key))
        + public_key
        + struct.pack("!H", len(cs_bytes))
        + cs_bytes
        + struct.pack("!BB", maximum_name_length & 0xFF, len(pub_bytes))
        + pub_bytes
        + struct.pack("!H", len(ext_bytes))
        + ext_bytes
    )
    return struct.pack("!HH", version, len(contents)) + contents


def encode_ech_config_list(raw_configs: Sequence[bytes]) -> bytes:
    """Wrap one or more encoded ``ECHConfig`` payloads in an ``ECHConfigList``."""
    body = b"".join(raw_configs)
    return struct.pack("!H", len(body)) + body
