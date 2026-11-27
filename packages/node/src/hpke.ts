import crypto from 'node:crypto';
import net from 'node:net';
import { NerutonError } from './errors.js';

// RFC 9180 HPKE algorithm identifiers
export const HPKE_KEM_P256_SHA256 = 0x0010;
export const HPKE_KEM_X25519_SHA256 = 0x0020;

export const HPKE_KDF_HKDF_SHA256 = 0x0001;

export const HPKE_AEAD_AES_128_GCM = 0x0001;
export const HPKE_AEAD_AES_256_GCM = 0x0002;
export const HPKE_AEAD_CHACHA20_POLY1305 = 0x0003;
export const HPKE_AEAD_EXPORT_ONLY = 0xffff;

export const HPKE_MODE_BASE = 0x00;
export const HPKE_NONCE_LEN = 12;
export const HPKE_TAG_LEN = 16;
export const HPKE_SHA256_LEN = 32;

/** Maximum allowed HPKE sequence number per RFC 9180 §5.2: `(1 << (8 * Nn)) - 1`. */
export const MAX_HPKE_SEQ = (1n << 96n) - 1n;

// RFC 9849 ECH wire version
export const ECH_VERSION = 0xfe0d;

// ASN.1 DER prefixes for raw 32-byte X25519 keys (RFC 8410)
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

// All 7 Curve25519 low-order u-coordinates with MSB of byte 31 masked (`& 0x7f`).
// Together with bit 255 = 0 or 1, these cover all 14 low-order X25519 point encodings (RFC 7748 §6.1):
// 0, 1, order-8 point 1, order-8 point 2, p - 1, p, and p + 1.
const X25519_LOW_ORDER_MASKED: readonly Buffer[] = [
  Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex'), // 0
  Buffer.from('0100000000000000000000000000000000000000000000000000000000000000', 'hex'), // 1
  Buffer.from('e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', 'hex'), // order 8
  Buffer.from('5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157', 'hex'), // order 8
  Buffer.from('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'), // p - 1
  Buffer.from('edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'), // p
  Buffer.from('eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', 'hex'), // p + 1
];

// NIST P-256 prime field parameters for strict on-curve validation (FIPS 186-4 / SEC 2)
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_A = P256_P - 3n;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

export type SupportedHpkeKemId = typeof HPKE_KEM_X25519_SHA256 | typeof HPKE_KEM_P256_SHA256;
export type SupportedHpkeKdfId = typeof HPKE_KDF_HKDF_SHA256;
export type SupportedHpkeAeadId =
  | typeof HPKE_AEAD_AES_128_GCM
  | typeof HPKE_AEAD_AES_256_GCM
  | typeof HPKE_AEAD_CHACHA20_POLY1305;

export interface HpkeSuite {
  readonly kemId: SupportedHpkeKemId;
  readonly kdfId: SupportedHpkeKdfId;
  readonly aeadId: SupportedHpkeAeadId;
}

export interface HpkeCipherSuite {
  readonly kdfId: number;
  readonly aeadId: number;
}

export interface EchConfigExtension {
  readonly type: number;
  readonly data: Buffer;
}

export interface ParsedEchConfig {
  readonly version: number;
  readonly configId: number;
  readonly kemId: number;
  readonly publicKey: Buffer;
  readonly cipherSuites: readonly HpkeCipherSuite[];
  readonly maximumNameLength: number;
  readonly publicName: string;
  readonly extensions: readonly EchConfigExtension[];
  /** Exact raw `ECHConfig` wire encoding (`version || length || contents`) for HPKE `info`. */
  readonly rawConfig: Buffer;
}

export interface SelectedEchConfig {
  readonly config: ParsedEchConfig;
  readonly suite: HpkeSuite;
}

export const ALL_SUPPORTED_HPKE_SUITES: readonly HpkeSuite[] = [
  { kemId: HPKE_KEM_X25519_SHA256, kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM },
  { kemId: HPKE_KEM_X25519_SHA256, kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_256_GCM },
  { kemId: HPKE_KEM_X25519_SHA256, kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_CHACHA20_POLY1305 },
  { kemId: HPKE_KEM_P256_SHA256, kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM },
  { kemId: HPKE_KEM_P256_SHA256, kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_256_GCM },
  { kemId: HPKE_KEM_P256_SHA256, kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_CHACHA20_POLY1305 },
] as const;

function u16be(value: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(value & 0xffff, 0);
  return b;
}

function bytesToBigIntBE(buf: Uint8Array): bigint {
  let v = 0n;
  for (let i = 0; i < buf.length; i += 1) {
    v = (v << 8n) | BigInt(buf[i]);
  }
  return v;
}

function isAllZeroConstantTime(buf: Uint8Array): boolean {
  let acc = 0;
  for (let i = 0; i < buf.length; i += 1) {
    acc |= buf[i];
  }
  return acc === 0;
}

/**
 * RFC 5869 `HKDF-Extract(salt, ikm)` for SHA-256 or SHA-384.
 */
export function hkdfExtract(
  hashAlg: 'sha256' | 'sha384',
  salt: Uint8Array,
  ikm: Uint8Array,
): Buffer {
  const hashLen = hashAlg === 'sha384' ? 48 : 32;
  const key = salt.length > 0 ? salt : Buffer.alloc(hashLen);
  return crypto.createHmac(hashAlg, key).update(ikm).digest();
}

/**
 * RFC 5869 `HKDF-Expand(prk, info, length)` for SHA-256 or SHA-384.
 */
export function hkdfExpand(
  hashAlg: 'sha256' | 'sha384',
  prk: Uint8Array,
  info: Uint8Array,
  length: number,
): Buffer {
  const hashLen = hashAlg === 'sha384' ? 48 : 32;
  if (length < 0 || length > 255 * hashLen) {
    throw new NerutonError(`HKDF-Expand length out of bounds: ${length}`, 'HPKE_ERROR');
  }
  if (length === 0) {
    return Buffer.alloc(0);
  }
  const n = Math.ceil(length / hashLen);
  const blocks: Buffer[] = [];
  let prev: Buffer = Buffer.alloc(0);
  for (let i = 1; i <= n; i += 1) {
    const hmac = crypto.createHmac(hashAlg, prk);
    if (prev.length > 0) {
      hmac.update(prev);
    }
    hmac.update(info);
    hmac.update(Buffer.from([i]));
    prev = hmac.digest();
    blocks.push(prev);
  }
  return Buffer.concat(blocks, n * hashLen).subarray(0, length);
}

const HPKE_VERSION_LABEL = Buffer.from('HPKE-v1', 'ascii');

function kemSuiteId(kemId: SupportedHpkeKemId): Buffer {
  return Buffer.concat([Buffer.from('KEM', 'ascii'), u16be(kemId)]);
}

function hpkeSuiteId(suite: HpkeSuite): Buffer {
  return Buffer.concat([
    Buffer.from('HPKE', 'ascii'),
    u16be(suite.kemId),
    u16be(suite.kdfId),
    u16be(suite.aeadId),
  ]);
}

function labeledExtract(
  suiteId: Buffer,
  salt: Uint8Array,
  label: string,
  ikm: Uint8Array,
): Buffer {
  const labeledIkm = Buffer.concat([
    HPKE_VERSION_LABEL,
    suiteId,
    Buffer.from(label, 'ascii'),
    Buffer.from(ikm),
  ]);
  try {
    return hkdfExtract('sha256', salt, labeledIkm);
  } finally {
    labeledIkm.fill(0);
  }
}

function labeledExpand(
  suiteId: Buffer,
  prk: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number,
): Buffer {
  const labeledInfo = Buffer.concat([
    u16be(length),
    HPKE_VERSION_LABEL,
    suiteId,
    Buffer.from(label, 'ascii'),
    Buffer.from(info),
  ]);
  return hkdfExpand('sha256', prk, labeledInfo, length);
}

/**
 * Strictly validate an uncompressed NIST P-256 public key (`0x04 || x(32) || y(32)`):
 * verifies exact length, uncompressed prefix, field bounds, and curve equation `y^2 ≡ x^3 - 3x + b (mod p)`.
 */
export function validateP256PublicKey(pk: Uint8Array): void {
  if (pk.length !== 65 || pk[0] !== 0x04) {
    throw new NerutonError(
      `invalid P-256 public key: expected 65-byte uncompressed SEC1 point (got ${pk.length} bytes)`,
      'HPKE_INVALID_KEY',
    );
  }
  const x = bytesToBigIntBE(pk.subarray(1, 33));
  const y = bytesToBigIntBE(pk.subarray(33, 65));
  if (x >= P256_P || y >= P256_P || (x === 0n && y === 0n)) {
    throw new NerutonError('invalid P-256 public key: coordinates out of field range', 'HPKE_INVALID_KEY');
  }
  const lhs = (y * y) % P256_P;
  const x2 = (x * x) % P256_P;
  const x3 = (x2 * x) % P256_P;
  const rhs = (x3 + P256_A * x + P256_B) % P256_P;
  if (lhs !== rhs) {
    throw new NerutonError('invalid P-256 public key: point is not on secp256r1 curve', 'HPKE_INVALID_KEY');
  }
}

/**
 * Strictly validate a raw 32-byte X25519 public key: checks exact length and rejects all 14
 * Curve25519 low-order point encodings (7 masked u-coordinates × MSB 0/1) in constant time.
 */
export function validateX25519PublicKey(pk: Uint8Array): void {
  if (pk.length !== 32) {
    throw new NerutonError(
      `invalid X25519 public key: expected 32 bytes (got ${pk.length})`,
      'HPKE_INVALID_KEY',
    );
  }
  const masked = Buffer.from(pk);
  masked[31] &= 0x7f;
  let isLowOrder = false;
  for (const bad of X25519_LOW_ORDER_MASKED) {
    if (crypto.timingSafeEqual(masked, bad)) {
      isLowOrder = true;
    }
  }
  if (isLowOrder) {
    throw new NerutonError(
      'invalid X25519 public key: low-order Curve25519 point',
      'HPKE_INVALID_KEY',
    );
  }
}

/**
 * Validate a KEM public key for `kemId`.
 */
export function validateKemPublicKey(kemId: SupportedHpkeKemId, pk: Uint8Array): void {
  if (kemId === HPKE_KEM_X25519_SHA256) {
    validateX25519PublicKey(pk);
  } else {
    validateP256PublicKey(pk);
  }
}

function createX25519PublicKeyObject(rawPub: Uint8Array): crypto.KeyObject {
  validateX25519PublicKey(rawPub);
  const der = Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(rawPub)]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function createX25519PrivateKeyObject(rawPriv: Uint8Array): crypto.KeyObject {
  if (rawPriv.length !== 32) {
    throw new NerutonError(`invalid X25519 private key length: ${rawPriv.length}`, 'HPKE_INVALID_KEY');
  }
  const der = Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(rawPriv)]);
  try {
    return crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } finally {
    der.fill(0);
  }
}

function exportRawX25519PublicKey(pubKey: crypto.KeyObject): Buffer {
  const spki = pubKey.export({ format: 'der', type: 'spki' }) as Buffer;
  if (spki.length !== 44) {
    throw new NerutonError(`unexpected X25519 SPKI DER length: ${spki.length}`, 'HPKE_ERROR');
  }
  return Buffer.from(spki.subarray(12));
}

function x25519Dh(privateKey: crypto.KeyObject, peerRawPub: Uint8Array): Buffer {
  const peerKey = createX25519PublicKeyObject(peerRawPub);
  let dh: Buffer;
  try {
    dh = crypto.diffieHellman({ privateKey, publicKey: peerKey });
  } catch (err) {
    throw new NerutonError(
      `X25519 key agreement failed: ${err instanceof Error ? err.message : String(err)}`,
      'HPKE_INVALID_KEY',
      { cause: err },
    );
  }
  // RFC 7748 §6.1 / RFC 9180 §7.1.4: reject all-zero shared secret (catches all low-order points).
  if (dh.length !== 32 || isAllZeroConstantTime(dh)) {
    dh.fill(0);
    throw new NerutonError('X25519 key agreement produced all-zero shared secret (low-order peer point)', 'HPKE_INVALID_KEY');
  }
  return dh;
}

function p256Dh(ecdh: crypto.ECDH, peerRawPub: Uint8Array): Buffer {
  validateP256PublicKey(peerRawPub);
  let dh: Buffer;
  try {
    dh = ecdh.computeSecret(peerRawPub);
  } catch (err) {
    throw new NerutonError(
      `P-256 ECDH key agreement failed: ${err instanceof Error ? err.message : String(err)}`,
      'HPKE_INVALID_KEY',
      { cause: err },
    );
  }
  if (dh.length !== 32) {
    dh.fill(0);
    throw new NerutonError(`unexpected P-256 shared secret length: ${dh.length}`, 'HPKE_ERROR');
  }
  return dh;
}

function extractAndExpand(kemId: SupportedHpkeKemId, dh: Buffer, kemContext: Buffer): Buffer {
  const suiteId = kemSuiteId(kemId);
  const eaePrk = labeledExtract(suiteId, Buffer.alloc(0), 'eae_prk', dh);
  try {
    return labeledExpand(suiteId, eaePrk, 'shared_secret', kemContext, HPKE_SHA256_LEN);
  } finally {
    eaePrk.fill(0);
  }
}

export interface KemEncapResult {
  readonly sharedSecret: Buffer;
  readonly enc: Buffer;
}

/**
 * RFC 9180 §4.1 `Encap(pkR)` (with optional deterministic ephemeral private key `skE` for test vectors).
 */
export function dhkemEncap(
  kemId: SupportedHpkeKemId,
  pkR: Uint8Array,
  deterministicSkE?: Uint8Array,
): KemEncapResult {
  const pkRBuf = Buffer.from(pkR);
  validateKemPublicKey(kemId, pkRBuf);

  if (kemId === HPKE_KEM_X25519_SHA256) {
    let privKey: crypto.KeyObject;
    let pubKey: crypto.KeyObject;
    if (deterministicSkE) {
      privKey = createX25519PrivateKeyObject(deterministicSkE);
      pubKey = crypto.createPublicKey(privKey);
    } else {
      const pair = crypto.generateKeyPairSync('x25519');
      privKey = pair.privateKey;
      pubKey = pair.publicKey;
    }
    const enc = exportRawX25519PublicKey(pubKey);
    const dh = x25519Dh(privKey, pkRBuf);
    try {
      const kemContext = Buffer.concat([enc, pkRBuf]);
      const sharedSecret = extractAndExpand(kemId, dh, kemContext);
      return { sharedSecret, enc };
    } finally {
      dh.fill(0);
    }
  }

  // DHKEM(P-256, HKDF-SHA256)
  const ecdh = crypto.createECDH('prime256v1');
  if (deterministicSkE) {
    if (deterministicSkE.length !== 32) {
      throw new NerutonError(`invalid P-256 private key length: ${deterministicSkE.length}`, 'HPKE_INVALID_KEY');
    }
    try {
      ecdh.setPrivateKey(deterministicSkE);
    } catch (err) {
      throw new NerutonError('invalid P-256 private key scalar', 'HPKE_INVALID_KEY', { cause: err });
    }
  } else {
    ecdh.generateKeys();
  }
  const enc = ecdh.getPublicKey(null, 'uncompressed');
  const dh = p256Dh(ecdh, pkRBuf);
  try {
    const kemContext = Buffer.concat([enc, pkRBuf]);
    const sharedSecret = extractAndExpand(kemId, dh, kemContext);
    return { sharedSecret, enc };
  } finally {
    dh.fill(0);
  }
}

/**
 * RFC 9180 §4.1 `Decap(enc, skR)` (used for unit tests and mock RFC 9849 ECH servers).
 */
export function dhkemDecap(
  kemId: SupportedHpkeKemId,
  enc: Uint8Array,
  skR: Uint8Array,
): Buffer {
  const encBuf = Buffer.from(enc);
  validateKemPublicKey(kemId, encBuf);

  if (kemId === HPKE_KEM_X25519_SHA256) {
    const privKey = createX25519PrivateKeyObject(skR);
    const pkR = exportRawX25519PublicKey(crypto.createPublicKey(privKey));
    const dh = x25519Dh(privKey, encBuf);
    try {
      const kemContext = Buffer.concat([encBuf, pkR]);
      return extractAndExpand(kemId, dh, kemContext);
    } finally {
      dh.fill(0);
    }
  }

  const ecdh = crypto.createECDH('prime256v1');
  if (skR.length !== 32) {
    throw new NerutonError(`invalid P-256 private key length: ${skR.length}`, 'HPKE_INVALID_KEY');
  }
  try {
    ecdh.setPrivateKey(skR);
  } catch (err) {
    throw new NerutonError('invalid P-256 private key scalar', 'HPKE_INVALID_KEY', { cause: err });
  }
  const pkR = ecdh.getPublicKey(null, 'uncompressed');
  const dh = p256Dh(ecdh, encBuf);
  try {
    const kemContext = Buffer.concat([encBuf, pkR]);
    return extractAndExpand(kemId, dh, kemContext);
  } finally {
    dh.fill(0);
  }
}

/**
 * Generate a fresh raw `(publicKey, privateKey)` keypair for a supported KEM.
 */
export function generateHpkeKeyPair(kemId: SupportedHpkeKemId): {
  publicKey: Buffer;
  privateKey: Buffer;
} {
  if (kemId === HPKE_KEM_X25519_SHA256) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
    const pk = exportRawX25519PublicKey(publicKey);
    const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
    const sk = Buffer.from(pkcs8.subarray(pkcs8.length - 32));
    pkcs8.fill(0);
    return { publicKey: pk, privateKey: sk };
  }
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  const pk = ecdh.getPublicKey(null, 'uncompressed');
  const rawSk = ecdh.getPrivateKey();
  const sk = rawSk.length === 32 ? Buffer.from(rawSk) : Buffer.concat([Buffer.alloc(32 - rawSk.length), rawSk]);
  return { publicKey: pk, privateKey: sk };
}

function aeadParams(aeadId: SupportedHpkeAeadId): {
  cipher: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305';
  keyLen: number;
} {
  switch (aeadId) {
    case HPKE_AEAD_AES_128_GCM:
      return { cipher: 'aes-128-gcm', keyLen: 16 };
    case HPKE_AEAD_AES_256_GCM:
      return { cipher: 'aes-256-gcm', keyLen: 32 };
    case HPKE_AEAD_CHACHA20_POLY1305:
      return { cipher: 'chacha20-poly1305', keyLen: 32 };
  }
}

function createAeadCipher(
  cipherName: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305',
  key: Buffer,
  nonce: Buffer,
): crypto.CipherGCM {
  if (cipherName === 'chacha20-poly1305') {
    return crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: HPKE_TAG_LEN });
  }
  return crypto.createCipheriv(cipherName, key, nonce, { authTagLength: HPKE_TAG_LEN });
}

function createAeadDecipher(
  cipherName: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305',
  key: Buffer,
  nonce: Buffer,
): crypto.DecipherGCM {
  if (cipherName === 'chacha20-poly1305') {
    return crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: HPKE_TAG_LEN });
  }
  return crypto.createDecipheriv(cipherName, key, nonce, { authTagLength: HPKE_TAG_LEN });
}

function computeHpkeNonce(baseNonce: Buffer, seq: bigint): Buffer {
  if (seq < 0n || seq > MAX_HPKE_SEQ) {
    throw new NerutonError('HPKE sequence number out of range', 'HPKE_SEQ_OVERFLOW');
  }
  const nonce = Buffer.from(baseNonce);
  let remaining = seq;
  for (let i = HPKE_NONCE_LEN - 1; i >= 0 && remaining > 0n; i -= 1) {
    nonce[i] ^= Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return nonce;
}

export interface HpkeKeyScheduleResult {
  readonly key: Buffer;
  readonly baseNonce: Buffer;
  readonly exporterSecret: Buffer;
}

/**
 * RFC 9180 §5.1 `KeySchedule(mode_base, shared_secret, info, "", "")`.
 */
export function hpkeKeyScheduleBase(
  suite: HpkeSuite,
  sharedSecret: Uint8Array,
  info: Uint8Array,
): HpkeKeyScheduleResult {
  const sid = hpkeSuiteId(suite);
  const { keyLen } = aeadParams(suite.aeadId);

  const pskIdHash = labeledExtract(sid, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0));
  const infoHash = labeledExtract(sid, Buffer.alloc(0), 'info_hash', info);
  const context = Buffer.concat([Buffer.from([HPKE_MODE_BASE]), pskIdHash, infoHash]);

  const secret = labeledExtract(sid, sharedSecret, 'secret', Buffer.alloc(0));
  try {
    const key = labeledExpand(sid, secret, 'key', context, keyLen);
    const baseNonce = labeledExpand(sid, secret, 'base_nonce', context, HPKE_NONCE_LEN);
    const exporterSecret = labeledExpand(sid, secret, 'exp', context, HPKE_SHA256_LEN);
    return { key, baseNonce, exporterSecret };
  } finally {
    secret.fill(0);
  }
}

/**
 * Stateful RFC 9180 Base-mode sender context (`ContextS`).
 */
export class HpkeSealer {
  readonly suite: HpkeSuite;
  private readonly cipherName: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305';
  private readonly key: Buffer;
  private readonly baseNonce: Buffer;
  private _seq = 0n;
  private destroyed = false;

  constructor(suite: HpkeSuite, key: Buffer, baseNonce: Buffer, initialSeq = 0n) {
    const params = aeadParams(suite.aeadId);
    if (key.length !== params.keyLen) {
      throw new NerutonError(`HPKE key length mismatch: expected ${params.keyLen}, got ${key.length}`, 'HPKE_ERROR');
    }
    if (baseNonce.length !== HPKE_NONCE_LEN) {
      throw new NerutonError(`HPKE base_nonce length mismatch: ${baseNonce.length}`, 'HPKE_ERROR');
    }
    if (initialSeq < 0n || initialSeq > MAX_HPKE_SEQ) {
      throw new NerutonError('HPKE initial sequence number out of range', 'HPKE_SEQ_OVERFLOW');
    }
    this.suite = suite;
    this.cipherName = params.cipher;
    this.key = Buffer.from(key);
    this.baseNonce = Buffer.from(baseNonce);
    this._seq = initialSeq;
  }

  get seq(): bigint {
    return this._seq;
  }

  /** @internal Exposed for deterministic RFC 9180 sequence vector & overflow testing. */
  setSeq(seq: bigint): void {
    if (seq < 0n || seq > MAX_HPKE_SEQ) {
      throw new NerutonError('HPKE sequence number out of range', 'HPKE_SEQ_OVERFLOW');
    }
    this._seq = seq;
  }

  seal(aad: Uint8Array, plaintext: Uint8Array): Buffer {
    if (this.destroyed) {
      throw new NerutonError('HPKE sealer has been destroyed', 'HPKE_ERROR');
    }
    // RFC 9180 §5.2: IncrementSeq rejects when seq >= (1 << (8*Nn)) - 1; check BEFORE sealing so seq never wraps.
    if (this._seq >= MAX_HPKE_SEQ) {
      throw new NerutonError('HPKE message limit reached (sequence number overflow)', 'HPKE_SEQ_OVERFLOW');
    }
    const nonce = computeHpkeNonce(this.baseNonce, this._seq);
    const cipher = createAeadCipher(this.cipherName, this.key, nonce);
    cipher.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    this._seq += 1n;
    return Buffer.concat([ct, tag]);
  }

  destroy(): void {
    this.destroyed = true;
    this.key.fill(0);
    this.baseNonce.fill(0);
  }
}

/**
 * Stateful RFC 9180 Base-mode recipient context (`ContextR`).
 */
export class HpkeOpener {
  readonly suite: HpkeSuite;
  private readonly cipherName: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305';
  private readonly key: Buffer;
  private readonly baseNonce: Buffer;
  private _seq = 0n;
  private destroyed = false;

  constructor(suite: HpkeSuite, key: Buffer, baseNonce: Buffer, initialSeq = 0n) {
    const params = aeadParams(suite.aeadId);
    if (key.length !== params.keyLen) {
      throw new NerutonError(`HPKE key length mismatch: expected ${params.keyLen}, got ${key.length}`, 'HPKE_ERROR');
    }
    if (baseNonce.length !== HPKE_NONCE_LEN) {
      throw new NerutonError(`HPKE base_nonce length mismatch: ${baseNonce.length}`, 'HPKE_ERROR');
    }
    if (initialSeq < 0n || initialSeq > MAX_HPKE_SEQ) {
      throw new NerutonError('HPKE initial sequence number out of range', 'HPKE_SEQ_OVERFLOW');
    }
    this.suite = suite;
    this.cipherName = params.cipher;
    this.key = Buffer.from(key);
    this.baseNonce = Buffer.from(baseNonce);
    this._seq = initialSeq;
  }

  get seq(): bigint {
    return this._seq;
  }

  open(aad: Uint8Array, ciphertext: Uint8Array): Buffer {
    if (this.destroyed) {
      throw new NerutonError('HPKE opener has been destroyed', 'HPKE_ERROR');
    }
    if (this._seq >= MAX_HPKE_SEQ) {
      throw new NerutonError('HPKE message limit reached (sequence number overflow)', 'HPKE_SEQ_OVERFLOW');
    }
    if (ciphertext.length < HPKE_TAG_LEN) {
      throw new NerutonError('HPKE ciphertext shorter than authentication tag', 'HPKE_OPEN_ERROR');
    }
    const nonce = computeHpkeNonce(this.baseNonce, this._seq);
    const body = ciphertext.subarray(0, ciphertext.length - HPKE_TAG_LEN);
    const tag = ciphertext.subarray(ciphertext.length - HPKE_TAG_LEN);
    const decipher = createAeadDecipher(this.cipherName, this.key, nonce);
    decipher.setAAD(Buffer.from(aad));
    decipher.setAuthTag(Buffer.from(tag));
    let pt: Buffer;
    try {
      pt = Buffer.concat([decipher.update(body), decipher.final()]);
    } catch (err) {
      throw new NerutonError('HPKE AEAD decryption failed', 'HPKE_OPEN_ERROR', { cause: err });
    }
    this._seq += 1n;
    return pt;
  }

  destroy(): void {
    this.destroyed = true;
    this.key.fill(0);
    this.baseNonce.fill(0);
  }
}

export interface SetupBaseSResult {
  readonly enc: Buffer;
  readonly sealer: HpkeSealer;
  readonly sharedSecret: Buffer;
  readonly key: Buffer;
  readonly baseNonce: Buffer;
  readonly exporterSecret: Buffer;
}

/**
 * RFC 9180 §5.1.1 `SetupBaseS(pkR, info)` (with optional deterministic `skE` for RFC 9180 vectors).
 */
export function setupBaseS(
  suite: HpkeSuite,
  pkR: Uint8Array,
  info: Uint8Array,
  deterministicSkE?: Uint8Array,
): SetupBaseSResult {
  const { sharedSecret, enc } = dhkemEncap(suite.kemId, pkR, deterministicSkE);
  const ks = hpkeKeyScheduleBase(suite, sharedSecret, info);
  const sealer = new HpkeSealer(suite, ks.key, ks.baseNonce);
  return {
    enc,
    sealer,
    sharedSecret,
    key: ks.key,
    baseNonce: ks.baseNonce,
    exporterSecret: ks.exporterSecret,
  };
}

/**
 * RFC 9180 §5.1.1 `SetupBaseR(enc, skR, info)`.
 */
export function setupBaseR(
  suite: HpkeSuite,
  enc: Uint8Array,
  skR: Uint8Array,
  info: Uint8Array,
): HpkeOpener {
  const sharedSecret = dhkemDecap(suite.kemId, enc, skR);
  try {
    const ks = hpkeKeyScheduleBase(suite, sharedSecret, info);
    try {
      return new HpkeOpener(suite, ks.key, ks.baseNonce);
    } finally {
      ks.key.fill(0);
      ks.baseNonce.fill(0);
      ks.exporterSecret.fill(0);
    }
  } finally {
    sharedSecret.fill(0);
  }
}

// ---------------------------------------------------------------------------
// RFC 9849 ECHConfigList parsing, encoding, and suite selection
// ---------------------------------------------------------------------------

function isValidPublicName(name: string): boolean {
  if (name.length === 0 || name.length > 255) {
    return false;
  }
  if (net.isIP(name) !== 0) {
    return false;
  }
  if (name.startsWith('.') || name.endsWith('.')) {
    return false;
  }
  const labels = name.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return false;
    }
    if (!/^[A-Za-z0-9-]+$/.test(label) || label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
  }
  return true;
}

function isSupportedKem(kemId: number): kemId is SupportedHpkeKemId {
  return kemId === HPKE_KEM_X25519_SHA256 || kemId === HPKE_KEM_P256_SHA256;
}

function isSupportedKdf(kdfId: number): kdfId is SupportedHpkeKdfId {
  return kdfId === HPKE_KDF_HKDF_SHA256;
}

function isSupportedAead(aeadId: number): aeadId is SupportedHpkeAeadId {
  return (
    aeadId === HPKE_AEAD_AES_128_GCM ||
    aeadId === HPKE_AEAD_AES_256_GCM ||
    aeadId === HPKE_AEAD_CHACHA20_POLY1305
  );
}

/**
 * Decode a base64-encoded `ECHConfigList` string (strict validation).
 */
export function decodeEchConfigBase64(base64Value: string): Buffer {
  const compact = base64Value.replace(/\s+/g, '');
  if (
    compact.length === 0 ||
    compact.length % 4 === 1 ||
    (compact.includes('=') && compact.length % 4 !== 0) ||
    !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)
  ) {
    throw new NerutonError('invalid base64 encoding in echConfig', 'ECH_INVALID_CONFIG');
  }
  const raw = Buffer.from(compact, 'base64');
  if (raw.length < 4) {
    throw new NerutonError('echConfig is too short to be a valid ECHConfigList', 'ECH_INVALID_CONFIG');
  }
  return raw;
}

/**
 * Parse an RFC 9849 §4 `ECHConfigList` wire buffer into all syntactically valid `0xfe0d` configs.
 * Unsupported versions are skipped cleanly; structurally malformed buffers throw `NerutonError('ECH_INVALID_CONFIG')`.
 */
export function parseEchConfigList(buf: Uint8Array): ParsedEchConfig[] {
  const data = Buffer.from(buf);
  if (data.length < 2) {
    throw new NerutonError('ECHConfigList truncated (missing 2-byte length prefix)', 'ECH_INVALID_CONFIG');
  }
  const totalLen = data.readUInt16BE(0);
  if (totalLen === 0 || 2 + totalLen !== data.length) {
    throw new NerutonError(
      `ECHConfigList length mismatch: header declares ${totalLen} bytes, buffer has ${data.length - 2}`,
      'ECH_INVALID_CONFIG',
    );
  }

  const results: ParsedEchConfig[] = [];
  let pos = 2;
  const end = data.length;

  while (pos < end) {
    if (pos + 4 > end) {
      throw new NerutonError('ECHConfig truncated in header', 'ECH_INVALID_CONFIG');
    }
    const entryStart = pos;
    const version = data.readUInt16BE(pos);
    const contentsLen = data.readUInt16BE(pos + 2);
    pos += 4;
    if (pos + contentsLen > end) {
      throw new NerutonError('ECHConfig contents length exceeds ECHConfigList bounds', 'ECH_INVALID_CONFIG');
    }
    const contentsEnd = pos + contentsLen;
    const rawConfig = Buffer.from(data.subarray(entryStart, contentsEnd));

    if (version !== ECH_VERSION) {
      // RFC 9849 §4: ignore configs with unknown versions.
      pos = contentsEnd;
      continue;
    }

    let cPos = pos;
    if (cPos + 5 > contentsEnd) {
      throw new NerutonError('ECHConfigContents truncated before public_key', 'ECH_INVALID_CONFIG');
    }
    const configId = data[cPos];
    const kemId = data.readUInt16BE(cPos + 1);
    const pkLen = data.readUInt16BE(cPos + 3);
    cPos += 5;
    if (pkLen === 0 || cPos + pkLen > contentsEnd) {
      throw new NerutonError('ECHConfigContents invalid or truncated public_key', 'ECH_INVALID_CONFIG');
    }
    const publicKey = Buffer.from(data.subarray(cPos, cPos + pkLen));
    cPos += pkLen;

    if (cPos + 2 > contentsEnd) {
      throw new NerutonError('ECHConfigContents truncated before cipher_suites', 'ECH_INVALID_CONFIG');
    }
    const csLen = data.readUInt16BE(cPos);
    cPos += 2;
    if (csLen < 4 || csLen % 4 !== 0 || cPos + csLen > contentsEnd) {
      throw new NerutonError('ECHConfigContents invalid cipher_suites length', 'ECH_INVALID_CONFIG');
    }
    const cipherSuites: HpkeCipherSuite[] = [];
    for (let i = 0; i < csLen; i += 4) {
      cipherSuites.push({
        kdfId: data.readUInt16BE(cPos + i),
        aeadId: data.readUInt16BE(cPos + i + 2),
      });
    }
    cPos += csLen;

    if (cPos + 2 > contentsEnd) {
      throw new NerutonError('ECHConfigContents truncated before public_name', 'ECH_INVALID_CONFIG');
    }
    const maximumNameLength = data[cPos];
    const nameLen = data[cPos + 1];
    cPos += 2;
    if (nameLen === 0 || cPos + nameLen > contentsEnd) {
      throw new NerutonError('ECHConfigContents invalid or truncated public_name', 'ECH_INVALID_CONFIG');
    }
    // Use latin1 (NOT ascii) so high-bit bytes >= 0x80 are preserved and rejected by isValidPublicName.
    const publicName = data.subarray(cPos, cPos + nameLen).toString('latin1');
    cPos += nameLen;

    if (cPos + 2 > contentsEnd) {
      throw new NerutonError('ECHConfigContents truncated before extensions', 'ECH_INVALID_CONFIG');
    }
    const extsLen = data.readUInt16BE(cPos);
    cPos += 2;
    if (cPos + extsLen !== contentsEnd) {
      throw new NerutonError('ECHConfigContents extensions length mismatch', 'ECH_INVALID_CONFIG');
    }

    const extensions: EchConfigExtension[] = [];
    const seenExtTypes = new Set<number>();
    let hasDuplicateExt = false;
    let hasUnknownMandatoryExt = false;

    while (cPos < contentsEnd) {
      if (cPos + 4 > contentsEnd) {
        throw new NerutonError('ECHConfigContents truncated extension header', 'ECH_INVALID_CONFIG');
      }
      const extType = data.readUInt16BE(cPos);
      const extLen = data.readUInt16BE(cPos + 2);
      cPos += 4;
      if (cPos + extLen > contentsEnd) {
        throw new NerutonError('ECHConfigContents truncated extension data', 'ECH_INVALID_CONFIG');
      }
      if (seenExtTypes.has(extType)) {
        hasDuplicateExt = true;
      }
      seenExtTypes.add(extType);
      // RFC 9849 §4: extensions with high bit set (0x8000) are mandatory; skip config if unknown.
      if ((extType & 0x8000) !== 0) {
        hasUnknownMandatoryExt = true;
      }
      extensions.push({
        type: extType,
        data: Buffer.from(data.subarray(cPos, cPos + extLen)),
      });
      cPos += extLen;
    }

    pos = contentsEnd;

    if (!isValidPublicName(publicName) || hasDuplicateExt || hasUnknownMandatoryExt) {
      continue;
    }

    results.push({
      version,
      configId,
      kemId,
      publicKey,
      cipherSuites,
      maximumNameLength,
      publicName,
      extensions,
      rawConfig,
    });
  }

  return results;
}

/**
 * Select the first compatible `ECHConfig` and HPKE suite from one or more `ECHConfigList` buffers.
 * Returns `null` if no compatible configuration is found (without throwing on malformed inputs).
 */
export function selectEchConfig(
  echConfigLists: Uint8Array | readonly Uint8Array[],
): SelectedEchConfig | null {
  const lists: readonly Uint8Array[] =
    echConfigLists instanceof Uint8Array ? [echConfigLists] : echConfigLists;

  for (const rawList of lists) {
    let parsed: ParsedEchConfig[];
    try {
      parsed = parseEchConfigList(rawList);
    } catch {
      continue;
    }

    for (const cfg of parsed) {
      if (!isSupportedKem(cfg.kemId)) {
        continue;
      }
      try {
        validateKemPublicKey(cfg.kemId, cfg.publicKey);
      } catch {
        continue;
      }

      for (const cs of cfg.cipherSuites) {
        if (cs.aeadId === HPKE_AEAD_EXPORT_ONLY) {
          continue;
        }
        if (isSupportedKdf(cs.kdfId) && isSupportedAead(cs.aeadId)) {
          return {
            config: cfg,
            suite: {
              kemId: cfg.kemId,
              kdfId: cs.kdfId,
              aeadId: cs.aeadId,
            },
          };
        }
      }
    }
  }

  return null;
}

/**
 * Inspect an `ECHConfigList` wire buffer and return the `public_name` of the first compatible config.
 */
export function selectEchPublicName(echConfigList: Uint8Array): string | null {
  return selectEchConfig(echConfigList)?.config.publicName ?? null;
}

/**
 * Encode a single RFC 9849 `ECHConfig` (`version || length || contents`).
 */
export function encodeEchConfig(params: {
  configId: number;
  kemId: number;
  publicKey: Uint8Array;
  cipherSuites: readonly HpkeCipherSuite[];
  maximumNameLength?: number;
  publicName: string;
  extensions?: readonly EchConfigExtension[];
  version?: number;
}): Buffer {
  const version = params.version ?? ECH_VERSION;
  const pk = Buffer.from(params.publicKey);
  const nameBuf = Buffer.from(params.publicName, 'ascii');
  const maxNameLen = params.maximumNameLength ?? 64;

  const csBuf = Buffer.alloc(params.cipherSuites.length * 4);
  for (let i = 0; i < params.cipherSuites.length; i += 1) {
    csBuf.writeUInt16BE(params.cipherSuites[i].kdfId, i * 4);
    csBuf.writeUInt16BE(params.cipherSuites[i].aeadId, i * 4 + 2);
  }

  const extParts: Buffer[] = [];
  for (const ext of params.extensions ?? []) {
    extParts.push(u16be(ext.type), u16be(ext.data.length), ext.data);
  }
  const extsBuf = Buffer.concat(extParts);

  const contents = Buffer.concat([
    Buffer.from([params.configId & 0xff]),
    u16be(params.kemId),
    u16be(pk.length),
    pk,
    u16be(csBuf.length),
    csBuf,
    Buffer.from([maxNameLen & 0xff, nameBuf.length & 0xff]),
    nameBuf,
    u16be(extsBuf.length),
    extsBuf,
  ]);

  return Buffer.concat([u16be(version), u16be(contents.length), contents]);
}

/**
 * Wrap one or more encoded `ECHConfig` buffers into an RFC 9849 `ECHConfigList`.
 */
export function encodeEchConfigList(encodedConfigs: readonly Uint8Array[]): Buffer {
  const body = Buffer.concat(encodedConfigs.map((c) => Buffer.from(c)));
  return Buffer.concat([u16be(body.length), body]);
}
