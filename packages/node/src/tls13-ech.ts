import crypto from 'node:crypto';
import net from 'node:net';
import { Duplex } from 'node:stream';
import tls from 'node:tls';
import { isIpLiteral, stripBrackets } from './doh.js';
import { NerutonError } from './errors.js';
import {
  ECH_VERSION,
  HPKE_TAG_LEN,
  HpkeSealer,
  hkdfExpand,
  hkdfExtract,
  parseEchConfigList,
  selectEchConfig,
  setupBaseS,
  validateP256PublicKey,
  validateX25519PublicKey,
  type ParsedEchConfig,
  type SelectedEchConfig,
} from './hpke.js';

// TLS 1.3 Record Content Types (RFC 8446 §5.1)
export const TLS_CONTENT_CHANGE_CIPHER_SPEC = 0x14;
export const TLS_CONTENT_ALERT = 0x15;
export const TLS_CONTENT_HANDSHAKE = 0x16;
export const TLS_CONTENT_APPLICATION_DATA = 0x17;

// TLS 1.3 Handshake Message Types (RFC 8446 §4)
export const TLS_HS_CLIENT_HELLO = 0x01;
export const TLS_HS_SERVER_HELLO = 0x02;
export const TLS_HS_NEW_SESSION_TICKET = 0x04;
export const TLS_HS_ENCRYPTED_EXTENSIONS = 0x08;
export const TLS_HS_CERTIFICATE = 0x0b;
export const TLS_HS_CERTIFICATE_REQUEST = 0x0d;
export const TLS_HS_CERTIFICATE_VERIFY = 0x0f;
export const TLS_HS_FINISHED = 0x14;
export const TLS_HS_KEY_UPDATE = 0x18;
export const TLS_HS_MESSAGE_HASH = 0xfe;

// TLS 1.3 Cipher Suites (RFC 8446 §B.4)
export const TLS_AES_128_GCM_SHA256 = 0x1301;
export const TLS_AES_256_GCM_SHA384 = 0x1302;
export const TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

// TLS 1.3 Named Groups (RFC 8446 §4.2.7)
export const TLS_GROUP_SECP256R1 = 0x0017;
export const TLS_GROUP_X25519 = 0x001d;

// TLS 1.3 Signature Algorithms (RFC 8446 §4.2.3)
export const TLS_SIG_ECDSA_SECP256R1_SHA256 = 0x0403;
export const TLS_SIG_ECDSA_SECP384R1_SHA384 = 0x0503;
export const TLS_SIG_RSA_PSS_RSAE_SHA256 = 0x0804;
export const TLS_SIG_RSA_PSS_RSAE_SHA384 = 0x0805;
export const TLS_SIG_RSA_PSS_RSAE_SHA512 = 0x0806;
export const TLS_SIG_ED25519 = 0x0807;
export const TLS_SIG_RSA_PSS_PSS_SHA256 = 0x0809;
export const TLS_SIG_RSA_PSS_PSS_SHA384 = 0x080a;
export const TLS_SIG_RSA_PSS_PSS_SHA512 = 0x080b;

// TLS Extensions
export const TLS_EXT_SERVER_NAME = 0x0000;
export const TLS_EXT_SUPPORTED_GROUPS = 0x000a;
export const TLS_EXT_SIGNATURE_ALGORITHMS = 0x000d;
export const TLS_EXT_ALPN = 0x0010;
export const TLS_EXT_SUPPORTED_VERSIONS = 0x002b;
export const TLS_EXT_COOKIE = 0x002c;
export const TLS_EXT_KEY_SHARE = 0x0033;
export const TLS_EXT_ECH = ECH_VERSION; // 0xfe0d

// ECH ClientHelloType (RFC 9849 §5)
export const ECH_CLIENT_HELLO_OUTER = 0x00;
export const ECH_CLIENT_HELLO_INNER = 0x01;

// TLS Alerts (RFC 8446 §6 & RFC 9849 §11.2)
export const TLS_ALERT_WARNING = 1;
export const TLS_ALERT_FATAL = 2;
export const TLS_ALERT_CLOSE_NOTIFY = 0;
export const TLS_ALERT_UNEXPECTED_MESSAGE = 10;
export const TLS_ALERT_BAD_RECORD_MAC = 20;
export const TLS_ALERT_RECORD_OVERFLOW = 22;
export const TLS_ALERT_HANDSHAKE_FAILURE = 40;
export const TLS_ALERT_BAD_CERTIFICATE = 42;
export const TLS_ALERT_CERTIFICATE_EXPIRED = 45;
export const TLS_ALERT_ILLEGAL_PARAMETER = 47;
export const TLS_ALERT_UNKNOWN_CA = 48;
export const TLS_ALERT_DECODE_ERROR = 50;
export const TLS_ALERT_DECRYPT_ERROR = 51;
export const TLS_ALERT_PROTOCOL_VERSION = 70;
export const TLS_ALERT_INTERNAL_ERROR = 80;
export const TLS_ALERT_MISSING_EXTENSION = 109;
export const TLS_ALERT_UNSUPPORTED_EXTENSION = 110;
export const TLS_ALERT_ECH_REQUIRED = 0x79; // 121

// Record layer limits (RFC 8446 §5.1 / §5.2)
export const TLS_MAX_PLAINTEXT = 16384;
export const TLS_MAX_CIPHERTEXT = 16384 + 256;
const TLS_MAX_SEQ = (1n << 64n) - 1n;

// RFC 8446 §4.1.3 HelloRetryRequest sentinel random
export const TLS_HRR_RANDOM = Buffer.from(
  'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c',
  'hex',
);

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

const OFFERED_CIPHER_SUITES = [
  TLS_AES_128_GCM_SHA256,
  TLS_AES_256_GCM_SHA384,
  TLS_CHACHA20_POLY1305_SHA256,
] as const;

const OFFERED_SIGNATURE_ALGORITHMS = [
  TLS_SIG_ECDSA_SECP256R1_SHA256,
  TLS_SIG_ECDSA_SECP384R1_SHA384,
  TLS_SIG_ED25519,
  TLS_SIG_RSA_PSS_RSAE_SHA256,
  TLS_SIG_RSA_PSS_RSAE_SHA384,
  TLS_SIG_RSA_PSS_RSAE_SHA512,
  TLS_SIG_RSA_PSS_PSS_SHA256,
  TLS_SIG_RSA_PSS_PSS_SHA384,
  TLS_SIG_RSA_PSS_PSS_SHA512,
] as const;

const OFFERED_SIGNATURE_SET = new Set<number>(OFFERED_SIGNATURE_ALGORITHMS);

const EKU_SERVER_AUTH_OID = '1.3.6.1.5.5.7.3.1';
const EKU_ANY_OID = '2.5.29.37.0';
const MAX_CERT_CHAIN_DEPTH = 10;
const MAX_IGNORED_CCS = 4;
const OID_BASIC_CONSTRAINTS = Buffer.from([0x55, 0x1d, 0x13]); // 2.5.29.19

export interface CipherSuiteSpec {
  readonly id: number;
  readonly name: string;
  readonly hashAlg: 'sha256' | 'sha384';
  readonly hashLen: 32 | 48;
  readonly aeadCipher: 'aes-128-gcm' | 'aes-256-gcm' | 'chacha20-poly1305';
  readonly keyLen: 16 | 32;
  readonly ivLen: 12;
}

export function getCipherSuiteSpec(suiteId: number): CipherSuiteSpec | null {
  switch (suiteId) {
    case TLS_AES_128_GCM_SHA256:
      return {
        id: suiteId,
        name: 'TLS_AES_128_GCM_SHA256',
        hashAlg: 'sha256',
        hashLen: 32,
        aeadCipher: 'aes-128-gcm',
        keyLen: 16,
        ivLen: 12,
      };
    case TLS_AES_256_GCM_SHA384:
      return {
        id: suiteId,
        name: 'TLS_AES_256_GCM_SHA384',
        hashAlg: 'sha384',
        hashLen: 48,
        aeadCipher: 'aes-256-gcm',
        keyLen: 32,
        ivLen: 12,
      };
    case TLS_CHACHA20_POLY1305_SHA256:
      return {
        id: suiteId,
        name: 'TLS_CHACHA20_POLY1305_SHA256',
        hashAlg: 'sha256',
        hashLen: 32,
        aeadCipher: 'chacha20-poly1305',
        keyLen: 32,
        ivLen: 12,
      };
    default:
      return null;
  }
}

export class TlsProtocolError extends NerutonError {
  readonly alertDescription: number | undefined;

  constructor(
    message: string,
    opts?: { code?: string; alertDescription?: number; cause?: unknown },
  ) {
    super(
      message,
      opts?.code ?? 'TLS_HANDSHAKE_FAILED',
      opts?.cause !== undefined ? { cause: opts.cause } : undefined,
    );
    this.alertDescription = opts?.alertDescription;
  }
}

/**
 * Thrown when the server rejected ECH and authenticated its outer certificate for `publicName`.
 * Any `retryConfigs` supplied in `EncryptedExtensions` are authenticated and safe for a 1-shot retry.
 */
export class EchRejectedError extends NerutonError {
  readonly publicName: string;
  readonly retryConfigs: Buffer | undefined;

  constructor(message: string, opts: { publicName: string; retryConfigs?: Buffer }) {
    super(message, 'ECH_REJECTED');
    this.publicName = opts.publicName;
    this.retryConfigs = opts.retryConfigs;
  }
}

// ---------------------------------------------------------------------------
// Wire encoding & TLS 1.3 Key Schedule primitives (RFC 8446 §7)
// ---------------------------------------------------------------------------

function u16be(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
}

function u24be(n: number): Buffer {
  const b = Buffer.alloc(3);
  b[0] = (n >>> 16) & 0xff;
  b[1] = (n >>> 8) & 0xff;
  b[2] = n & 0xff;
  return b;
}

function readU24BE(buf: Buffer, offset: number): number {
  return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2];
}

export function tlsHash(hashAlg: 'sha256' | 'sha384', data: Uint8Array | readonly Uint8Array[]): Buffer {
  const h = crypto.createHash(hashAlg);
  if (data instanceof Uint8Array) {
    h.update(data);
  } else {
    for (const chunk of data) {
      h.update(chunk);
    }
  }
  return h.digest();
}

/**
 * RFC 8446 §7.1 `HKDF-Expand-Label(Secret, Label, Context, Length)`.
 */
export function hkdfExpandLabel(
  hashAlg: 'sha256' | 'sha384',
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number,
): Buffer {
  const fullLabel = Buffer.from(`tls13 ${label}`, 'ascii');
  if (fullLabel.length > 255 || context.length > 255) {
    throw new TlsProtocolError('HKDF-Expand-Label input too long');
  }
  const hkdfLabel = Buffer.concat([
    u16be(length),
    Buffer.from([fullLabel.length]),
    fullLabel,
    Buffer.from([context.length]),
    Buffer.from(context),
  ]);
  return hkdfExpand(hashAlg, secret, hkdfLabel, length);
}

/**
 * RFC 8446 §7.1 `Derive-Secret(Secret, Label, Messages)`.
 */
export function deriveSecret(
  hashAlg: 'sha256' | 'sha384',
  secret: Uint8Array,
  label: string,
  transcriptHash: Uint8Array,
): Buffer {
  const hashLen = hashAlg === 'sha384' ? 48 : 32;
  return hkdfExpandLabel(hashAlg, secret, label, transcriptHash, hashLen);
}

export function deriveTrafficKeys(
  suite: CipherSuiteSpec,
  trafficSecret: Uint8Array,
): { key: Buffer; iv: Buffer } {
  const key = hkdfExpandLabel(suite.hashAlg, trafficSecret, 'key', Buffer.alloc(0), suite.keyLen);
  const iv = hkdfExpandLabel(suite.hashAlg, trafficSecret, 'iv', Buffer.alloc(0), suite.ivLen);
  return { key, iv };
}

export function updateTrafficSecret(suite: CipherSuiteSpec, currentSecret: Uint8Array): Buffer {
  return hkdfExpandLabel(suite.hashAlg, currentSecret, 'traffic upd', Buffer.alloc(0), suite.hashLen);
}

export function computeFinishedVerifyData(
  suite: CipherSuiteSpec,
  baseKey: Uint8Array,
  transcriptHash: Uint8Array,
): Buffer {
  const finishedKey = hkdfExpandLabel(
    suite.hashAlg,
    baseKey,
    'finished',
    Buffer.alloc(0),
    suite.hashLen,
  );
  try {
    return crypto.createHmac(suite.hashAlg, finishedKey).update(transcriptHash).digest();
  } finally {
    finishedKey.fill(0);
  }
}

/**
 * Stateful TLS 1.3 AEAD record cipher (RFC 8446 §5.2) supporting KeyUpdate rotation.
 */
export class Tls13RecordCipher {
  readonly suite: CipherSuiteSpec;
  private secret: Buffer;
  private key: Buffer;
  private iv: Buffer;
  private _seq = 0n;
  private destroyed = false;

  constructor(suite: CipherSuiteSpec, trafficSecret: Uint8Array, initialSeq = 0n) {
    if (initialSeq < 0n || initialSeq > TLS_MAX_SEQ) {
      throw new TlsProtocolError('TLS record initial sequence number out of range', {
        alertDescription: TLS_ALERT_INTERNAL_ERROR,
      });
    }
    this.suite = suite;
    this.secret = Buffer.from(trafficSecret);
    const { key, iv } = deriveTrafficKeys(suite, this.secret);
    this.key = key;
    this.iv = iv;
    this._seq = initialSeq;
  }

  get seq(): bigint {
    return this._seq;
  }

  private computeNonce(seq: bigint): Buffer {
    const nonce = Buffer.from(this.iv);
    let rem = seq;
    for (let i = 11; i >= 4 && rem > 0n; i -= 1) {
      nonce[i] ^= Number(rem & 0xffn);
      rem >>= 8n;
    }
    return nonce;
  }

  /**
   * Encrypt one TLSInnerPlaintext fragment (`<= 16384` bytes, padded inner <= 16385) into a complete 5-byte-header TLS 1.3 record.
   */
  encryptRecord(innerContentType: number, content: Uint8Array, paddingZeros = 0): Buffer {
    if (this.destroyed) {
      throw new TlsProtocolError('TLS record cipher has been destroyed', {
        alertDescription: TLS_ALERT_INTERNAL_ERROR,
      });
    }
    if (paddingZeros < 0 || content.length > TLS_MAX_PLAINTEXT || content.length + paddingZeros > TLS_MAX_PLAINTEXT) {
      throw new TlsProtocolError(
        `TLS plaintext fragment exceeds ${TLS_MAX_PLAINTEXT} bytes`,
        { alertDescription: TLS_ALERT_RECORD_OVERFLOW },
      );
    }
    if (this._seq >= TLS_MAX_SEQ) {
      throw new TlsProtocolError('TLS record sequence number overflow', {
        alertDescription: TLS_ALERT_INTERNAL_ERROR,
      });
    }

    const innerLen = content.length + 1 + paddingZeros;
    const innerPlaintext = Buffer.alloc(innerLen);
    Buffer.from(content).copy(innerPlaintext, 0);
    innerPlaintext[content.length] = innerContentType & 0xff;
    // Remaining `paddingZeros` bytes are already 0x00.

    const encryptedLen = innerLen + HPKE_TAG_LEN;
    const header = Buffer.from([
      TLS_CONTENT_APPLICATION_DATA,
      0x03,
      0x03,
      (encryptedLen >>> 8) & 0xff,
      encryptedLen & 0xff,
    ]);

    const nonce = this.computeNonce(this._seq);
    const cipher =
      this.suite.aeadCipher === 'chacha20-poly1305'
        ? crypto.createCipheriv('chacha20-poly1305', this.key, nonce, { authTagLength: HPKE_TAG_LEN })
        : crypto.createCipheriv(this.suite.aeadCipher, this.key, nonce, { authTagLength: HPKE_TAG_LEN });
    cipher.setAAD(header);
    const ct = Buffer.concat([cipher.update(innerPlaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    this._seq += 1n;
    return Buffer.concat([header, ct, tag]);
  }

  /**
   * Decrypt a TLS 1.3 ApplicationData record payload (`header` = exact 5-byte record header, `ciphertext` = body + 16B tag),
   * stripping trailing `0x00` inner plaintext padding and returning `{ contentType, content }`.
   */
  decryptRecord(header: Buffer, ciphertext: Buffer): { contentType: number; content: Buffer } {
    if (this.destroyed) {
      throw new TlsProtocolError('TLS record cipher has been destroyed', {
        alertDescription: TLS_ALERT_INTERNAL_ERROR,
      });
    }
    if (ciphertext.length < HPKE_TAG_LEN + 1) {
      throw new TlsProtocolError('TLS encrypted record too short', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    if (ciphertext.length > TLS_MAX_CIPHERTEXT) {
      throw new TlsProtocolError('TLS encrypted record exceeds 16640 bytes', {
        alertDescription: TLS_ALERT_RECORD_OVERFLOW,
      });
    }
    if (this._seq >= TLS_MAX_SEQ) {
      throw new TlsProtocolError('TLS record sequence number overflow', {
        alertDescription: TLS_ALERT_INTERNAL_ERROR,
      });
    }

    const nonce = this.computeNonce(this._seq);
    const body = ciphertext.subarray(0, ciphertext.length - HPKE_TAG_LEN);
    const tag = ciphertext.subarray(ciphertext.length - HPKE_TAG_LEN);

    const decipher =
      this.suite.aeadCipher === 'chacha20-poly1305'
        ? crypto.createDecipheriv('chacha20-poly1305', this.key, nonce, { authTagLength: HPKE_TAG_LEN })
        : crypto.createDecipheriv(this.suite.aeadCipher, this.key, nonce, { authTagLength: HPKE_TAG_LEN });
    decipher.setAAD(header);
    decipher.setAuthTag(tag);

    let plaintext: Buffer;
    try {
      plaintext = Buffer.concat([decipher.update(body), decipher.final()]);
    } catch (err) {
      throw new TlsProtocolError('TLS record AEAD decryption failed (bad_record_mac)', {
        alertDescription: TLS_ALERT_BAD_RECORD_MAC,
        cause: err,
      });
    }
    this._seq += 1n;

    // RFC 8446 §5.4: full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1 octets.
    if (plaintext.length > TLS_MAX_PLAINTEXT + 1) {
      throw new TlsProtocolError('TLS inner plaintext exceeds 16385 bytes', {
        alertDescription: TLS_ALERT_RECORD_OVERFLOW,
      });
    }

    // RFC 8446 §5.4: strip trailing zero padding; the last non-zero byte is the real ContentType.
    let end = plaintext.length - 1;
    while (end >= 0 && plaintext[end] === 0) {
      end -= 1;
    }
    if (end < 0) {
      throw new TlsProtocolError('TLS inner plaintext missing content type (all zeros)', {
        alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
      });
    }
    if (end > TLS_MAX_PLAINTEXT) {
      throw new TlsProtocolError('TLS inner plaintext exceeds 16384 bytes', {
        alertDescription: TLS_ALERT_RECORD_OVERFLOW,
      });
    }
    return {
      contentType: plaintext[end],
      content: Buffer.from(plaintext.subarray(0, end)),
    };
  }

  /**
   * Rotate traffic keys per RFC 8446 §7.2 (`KeyUpdate`).
   */
  rotateKeys(): void {
    if (this.destroyed) {
      throw new TlsProtocolError('TLS record cipher has been destroyed', {
        alertDescription: TLS_ALERT_INTERNAL_ERROR,
      });
    }
    const nextSecret = updateTrafficSecret(this.suite, this.secret);
    const { key, iv } = deriveTrafficKeys(this.suite, nextSecret);
    this.secret.fill(0);
    this.key.fill(0);
    this.iv.fill(0);
    this.secret = nextSecret;
    this.key = key;
    this.iv = iv;
    this._seq = 0n;
  }

  destroy(): void {
    this.destroyed = true;
    this.secret.fill(0);
    this.key.fill(0);
    this.iv.fill(0);
  }
}

// ---------------------------------------------------------------------------
// Key Exchange helpers (X25519 & secp256r1)
// ---------------------------------------------------------------------------

interface EphemeralKeyShare {
  readonly group: number;
  readonly publicKey: Buffer;
  computeSharedSecret(peerPublicKey: Buffer): Buffer;
}

function generateKeyShare(group: number): EphemeralKeyShare {
  if (group === TLS_GROUP_X25519) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('x25519');
    const spki = publicKey.export({ format: 'der', type: 'spki' }) as Buffer;
    const rawPub = Buffer.from(spki.subarray(12));
    return {
      group,
      publicKey: rawPub,
      computeSharedSecret(peerPub: Buffer): Buffer {
        let dh: Buffer;
        try {
          validateX25519PublicKey(peerPub);
          const peerObj = crypto.createPublicKey({
            key: Buffer.concat([X25519_SPKI_PREFIX, peerPub]),
            format: 'der',
            type: 'spki',
          });
          dh = crypto.diffieHellman({ privateKey, publicKey: peerObj });
        } catch (err) {
          throw new TlsProtocolError(
            `invalid X25519 key share: ${err instanceof Error ? err.message : String(err)}`,
            { alertDescription: TLS_ALERT_ILLEGAL_PARAMETER, cause: err },
          );
        }
        let acc = 0;
        for (let i = 0; i < dh.length; i += 1) acc |= dh[i];
        if (dh.length !== 32 || acc === 0) {
          dh.fill(0);
          throw new TlsProtocolError('X25519 key share produced all-zero shared secret', {
            alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
          });
        }
        return dh;
      },
    };
  }

  if (group === TLS_GROUP_SECP256R1) {
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const rawPub = ecdh.getPublicKey(null, 'uncompressed');
    return {
      group,
      publicKey: rawPub,
      computeSharedSecret(peerPub: Buffer): Buffer {
        let dh: Buffer;
        try {
          validateP256PublicKey(peerPub);
          dh = ecdh.computeSecret(peerPub);
        } catch (err) {
          throw new TlsProtocolError(
            `invalid P-256 key share: ${err instanceof Error ? err.message : String(err)}`,
            { alertDescription: TLS_ALERT_ILLEGAL_PARAMETER, cause: err },
          );
        }
        if (dh.length !== 32) {
          dh.fill(0);
          throw new TlsProtocolError('unexpected P-256 shared secret length', {
            alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
          });
        }
        return dh;
      },
    };
  }

  throw new TlsProtocolError(`unsupported TLS key exchange group 0x${group.toString(16)}`, {
    alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
  });
}

// ---------------------------------------------------------------------------
// Strict X.509 Certificate Chain & Identity Verification (Node >= 18.0 safe!)
// ---------------------------------------------------------------------------

let cachedDefaultRoots: crypto.X509Certificate[] | null = null;

function parseCertSource(source: string | Buffer | ReadonlyArray<string | Buffer>): crypto.X509Certificate[] {
  const items = Array.isArray(source) ? source : [source];
  const certs: crypto.X509Certificate[] = [];

  for (const item of items) {
    if (typeof item === 'string') {
      const matches = item.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      if (matches && matches.length > 0) {
        for (const pem of matches) {
          certs.push(new crypto.X509Certificate(pem));
        }
      } else if (item.trim().length > 0) {
        certs.push(new crypto.X509Certificate(item));
      }
      continue;
    }

    const buf = Buffer.from(item);
    const asText = buf.toString('utf8');
    if (asText.includes('-----BEGIN CERTIFICATE-----')) {
      const matches = asText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      if (matches) {
        for (const pem of matches) {
          certs.push(new crypto.X509Certificate(pem));
        }
      }
    } else if (buf.length > 0) {
      certs.push(new crypto.X509Certificate(buf));
    }
  }

  return certs;
}

function getTrustAnchors(ca?: string | Buffer | Array<string | Buffer>): crypto.X509Certificate[] {
  if (ca !== undefined) {
    return parseCertSource(ca);
  }
  if (!cachedDefaultRoots) {
    const roots: crypto.X509Certificate[] = [];
    for (const pem of tls.rootCertificates) {
      try {
        roots.push(new crypto.X509Certificate(pem));
      } catch {
        // Skip any unparseable platform root.
      }
    }
    cachedDefaultRoots = roots;
  }
  return cachedDefaultRoots;
}

function checkCertValidityWindow(cert: crypto.X509Certificate, nowMs: number): void {
  // Node 18.0 compatibility: MUST use Date.parse(validFrom/validTo), NOT validFromDate/validToDate.
  const notBefore = Date.parse(cert.validFrom);
  const notAfter = Date.parse(cert.validTo);
  if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
    throw new TlsProtocolError(`certificate '${cert.subject}' has unparseable validity dates`, {
      code: 'TLS_CERT_INVALID',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }
  if (nowMs < notBefore) {
    throw new TlsProtocolError(
      `certificate '${cert.subject}' is not yet valid (validFrom: ${cert.validFrom})`,
      { code: 'TLS_CERT_NOT_YET_VALID', alertDescription: TLS_ALERT_CERTIFICATE_EXPIRED },
    );
  }
  if (nowMs > notAfter) {
    throw new TlsProtocolError(
      `certificate '${cert.subject}' has expired (validTo: ${cert.validTo})`,
      { code: 'TLS_CERT_EXPIRED', alertDescription: TLS_ALERT_CERTIFICATE_EXPIRED },
    );
  }
}

function checkServerAuthEku(cert: crypto.X509Certificate): void {
  // In Node's crypto.X509Certificate, `keyUsage` returns Extended Key Usage OIDs when present.
  const ekus = cert.keyUsage;
  if (!ekus || ekus.length === 0) {
    return;
  }
  if (!ekus.includes(EKU_SERVER_AUTH_OID) && !ekus.includes(EKU_ANY_OID)) {
    throw new TlsProtocolError(
      `certificate '${cert.subject}' Extended Key Usage does not permit id-kp-serverAuth (${EKU_SERVER_AUTH_OID})`,
      { code: 'TLS_CERT_BAD_EKU', alertDescription: TLS_ALERT_BAD_CERTIFICATE },
    );
  }
}

function safeVerifySignature(child: crypto.X509Certificate, issuer: crypto.X509Certificate): boolean {
  try {
    return child.checkIssued(issuer) && child.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

interface DerElement {
  readonly tag: number;
  readonly valStart: number;
  readonly valEnd: number;
  readonly nextOffset: number;
}

function readDerElement(buf: Buffer, offset: number, end: number): DerElement {
  if (offset + 2 > end) {
    throw new TlsProtocolError('ASN.1 DER element truncated', {
      code: 'TLS_CERT_INVALID',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }
  const tag = buf[offset];
  const lenByte = buf[offset + 1];
  let len: number;
  let valStart: number;

  if (lenByte < 0x80) {
    len = lenByte;
    valStart = offset + 2;
  } else {
    const numOctets = lenByte & 0x7f;
    if (numOctets === 0 || numOctets > 4 || offset + 2 + numOctets > end) {
      throw new TlsProtocolError('invalid ASN.1 DER length encoding', {
        code: 'TLS_CERT_INVALID',
        alertDescription: TLS_ALERT_BAD_CERTIFICATE,
      });
    }
    if (buf[offset + 2] === 0x00) {
      throw new TlsProtocolError('non-minimal ASN.1 DER length encoding', {
        code: 'TLS_CERT_INVALID',
        alertDescription: TLS_ALERT_BAD_CERTIFICATE,
      });
    }
    len = 0;
    for (let i = 0; i < numOctets; i += 1) {
      len = len * 256 + buf[offset + 2 + i];
    }
    if (len < 0x80) {
      throw new TlsProtocolError('non-minimal ASN.1 DER long-form length', {
        code: 'TLS_CERT_INVALID',
        alertDescription: TLS_ALERT_BAD_CERTIFICATE,
      });
    }
    valStart = offset + 2 + numOctets;
  }

  const valEnd = valStart + len;
  if (valEnd > end) {
    throw new TlsProtocolError('ASN.1 DER element exceeds container bounds', {
      code: 'TLS_CERT_INVALID',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }
  return { tag, valStart, valEnd, nextOffset: valEnd };
}

interface ParsedCertConstraints {
  readonly isCa: boolean;
  readonly pathLenConstraint: number | null;
  readonly isSelfIssued: boolean;
}

/**
 * Strictly parse `TBSCertificate -> extensions -> BasicConstraints (OID 2.5.29.19)` and
 * exact DER `issuer`/`subject` equality from `cert.raw` (RFC 5280 §4.1, §4.2.1.9, §6.1.4).
 */
function parseCertBasicConstraints(rawDer: Buffer): ParsedCertConstraints {
  const certSeq = readDerElement(rawDer, 0, rawDer.length);
  if (certSeq.tag !== 0x30) {
    throw new TlsProtocolError('X.509 certificate is not an ASN.1 SEQUENCE', {
      code: 'TLS_CERT_INVALID',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }
  const tbs = readDerElement(rawDer, certSeq.valStart, certSeq.valEnd);
  if (tbs.tag !== 0x30) {
    throw new TlsProtocolError('X.509 TBSCertificate is not an ASN.1 SEQUENCE', {
      code: 'TLS_CERT_INVALID',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }

  let pos = tbs.valStart;
  let hasExplicitVersion = false;
  if (pos < tbs.valEnd && rawDer[pos] === 0xa0) {
    const verEl = readDerElement(rawDer, pos, tbs.valEnd);
    pos = verEl.nextOffset;
    hasExplicitVersion = true;
  }

  // serialNumber (INTEGER), signature (SEQUENCE), issuer (SEQUENCE), validity (SEQUENCE),
  // subject (SEQUENCE), subjectPublicKeyInfo (SEQUENCE)
  const serialEl = readDerElement(rawDer, pos, tbs.valEnd);
  if (serialEl.tag !== 0x02) {
    throw new TlsProtocolError('X.509 serialNumber is not an INTEGER', {
      code: 'TLS_CERT_INVALID',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }
  const sigAlgEl = readDerElement(rawDer, serialEl.nextOffset, tbs.valEnd);
  const issuerEl = readDerElement(rawDer, sigAlgEl.nextOffset, tbs.valEnd);
  const validityEl = readDerElement(rawDer, issuerEl.nextOffset, tbs.valEnd);
  const subjectEl = readDerElement(rawDer, validityEl.nextOffset, tbs.valEnd);
  const spkiEl = readDerElement(rawDer, subjectEl.nextOffset, tbs.valEnd);
  if (
    sigAlgEl.tag !== 0x30 ||
    issuerEl.tag !== 0x30 ||
    validityEl.tag !== 0x30 ||
    subjectEl.tag !== 0x30 ||
    spkiEl.tag !== 0x30
  ) {
    throw new TlsProtocolError('X.509 TBSCertificate mandatory field has invalid ASN.1 tag', {
      code: 'TLS_CERT_INVALID',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }

  const issuerDer = rawDer.subarray(issuerEl.valStart, issuerEl.valEnd);
  const subjectDer = rawDer.subarray(subjectEl.valStart, subjectEl.valEnd);
  const isSelfIssued = issuerDer.length > 0 && issuerDer.equals(subjectDer);

  pos = spkiEl.nextOffset;
  if (!hasExplicitVersion) {
    // v1 certificates have no extensions field.
    return { isCa: false, pathLenConstraint: null, isSelfIssued };
  }

  let isCa = false;
  let pathLenConstraint: number | null = null;
  let sawBasicConstraints = false;

  while (pos < tbs.valEnd) {
    const optEl = readDerElement(rawDer, pos, tbs.valEnd);
    pos = optEl.nextOffset;
    if (optEl.tag === 0x81 || optEl.tag === 0x82) {
      // issuerUniqueID [1] / subjectUniqueID [2]
      continue;
    }
    if (optEl.tag !== 0xa3) {
      continue;
    }

    // [3] EXPLICIT Extensions ::= SEQUENCE OF Extension
    const extsSeq = readDerElement(rawDer, optEl.valStart, optEl.valEnd);
    if (extsSeq.tag !== 0x30 || extsSeq.nextOffset !== optEl.valEnd) {
      throw new TlsProtocolError('malformed X.509 extensions wrapper', {
        code: 'TLS_CERT_INVALID',
        alertDescription: TLS_ALERT_BAD_CERTIFICATE,
      });
    }

    let extPos = extsSeq.valStart;
    while (extPos < extsSeq.valEnd) {
      const extSeq = readDerElement(rawDer, extPos, extsSeq.valEnd);
      if (extSeq.tag !== 0x30) {
        throw new TlsProtocolError('malformed X.509 Extension entry', {
          code: 'TLS_CERT_INVALID',
          alertDescription: TLS_ALERT_BAD_CERTIFICATE,
        });
      }
      extPos = extSeq.nextOffset;

      const oidEl = readDerElement(rawDer, extSeq.valStart, extSeq.valEnd);
      if (oidEl.tag !== 0x06) {
        throw new TlsProtocolError('malformed X.509 Extension OID', {
          code: 'TLS_CERT_INVALID',
          alertDescription: TLS_ALERT_BAD_CERTIFICATE,
        });
      }
      const oidBytes = rawDer.subarray(oidEl.valStart, oidEl.valEnd);
      if (!oidBytes.equals(OID_BASIC_CONSTRAINTS)) {
        continue;
      }

      if (sawBasicConstraints) {
        throw new TlsProtocolError('duplicate BasicConstraints extension in certificate', {
          code: 'TLS_CERT_INVALID',
          alertDescription: TLS_ALERT_BAD_CERTIFICATE,
        });
      }
      sawBasicConstraints = true;

      let fieldPos = oidEl.nextOffset;
      if (fieldPos < extSeq.valEnd && rawDer[fieldPos] === 0x01) {
        // Optional critical BOOLEAN
        const critEl = readDerElement(rawDer, fieldPos, extSeq.valEnd);
        fieldPos = critEl.nextOffset;
      }
      const valOctets = readDerElement(rawDer, fieldPos, extSeq.valEnd);
      if (valOctets.tag !== 0x04 || valOctets.nextOffset !== extSeq.valEnd) {
        throw new TlsProtocolError('malformed BasicConstraints extnValue OCTET STRING', {
          code: 'TLS_CERT_INVALID',
          alertDescription: TLS_ALERT_BAD_CERTIFICATE,
        });
      }

      const bcSeq = readDerElement(rawDer, valOctets.valStart, valOctets.valEnd);
      if (bcSeq.tag !== 0x30 || bcSeq.nextOffset !== valOctets.valEnd) {
        throw new TlsProtocolError('malformed BasicConstraints SEQUENCE', {
          code: 'TLS_CERT_INVALID',
          alertDescription: TLS_ALERT_BAD_CERTIFICATE,
        });
      }

      let bcPos = bcSeq.valStart;
      if (bcPos < bcSeq.valEnd && rawDer[bcPos] === 0x01) {
        const caBool = readDerElement(rawDer, bcPos, bcSeq.valEnd);
        if (caBool.valEnd - caBool.valStart !== 1) {
          throw new TlsProtocolError('malformed BasicConstraints cA BOOLEAN', {
            code: 'TLS_CERT_INVALID',
            alertDescription: TLS_ALERT_BAD_CERTIFICATE,
          });
        }
        isCa = rawDer[caBool.valStart] !== 0x00;
        bcPos = caBool.nextOffset;
      }

      if (bcPos < bcSeq.valEnd) {
        const pathLenEl = readDerElement(rawDer, bcPos, bcSeq.valEnd);
        if (
          pathLenEl.tag !== 0x02 ||
          pathLenEl.valEnd <= pathLenEl.valStart ||
          pathLenEl.nextOffset !== bcSeq.valEnd
        ) {
          throw new TlsProtocolError('malformed BasicConstraints pathLenConstraint INTEGER', {
            code: 'TLS_CERT_INVALID',
            alertDescription: TLS_ALERT_BAD_CERTIFICATE,
          });
        }
        // Negative pathLenConstraint is forbidden by RFC 5280 §4.2.1.9 (INTEGER (0..MAX)).
        if ((rawDer[pathLenEl.valStart] & 0x80) !== 0) {
          throw new TlsProtocolError('negative BasicConstraints pathLenConstraint', {
            code: 'TLS_CERT_INVALID',
            alertDescription: TLS_ALERT_BAD_CERTIFICATE,
          });
        }
        let val = 0n;
        for (let i = pathLenEl.valStart; i < pathLenEl.valEnd; i += 1) {
          val = (val << 8n) | BigInt(rawDer[i]);
        }
        pathLenConstraint = val > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(val);
      }
    }
  }

  return { isCa, pathLenConstraint, isSelfIssued };
}

/**
 * Strictly verify a DER certificate chain against `hostname` and the trust store (`ca` or `tls.rootCertificates`).
 * Checks:
 * - Validity period (`Date.parse(validFrom/validTo)`) on every cert in the verified path
 * - Extended Key Usage (`id-kp-serverAuth` or `anyExtendedKeyUsage`) when present on leaf/intermediates
 * - Hostname/IP identity via `tls.checkServerIdentity(hostname, leaf.toLegacyObject())`
 * - Cycle-guarded DFS chain building (max depth 10) requiring `issuer.ca === true`, `child.checkIssued(issuer)`, and `child.verify(issuer.publicKey)`.
 */
export function verifyX509Chain(
  certDers: readonly Buffer[],
  hostname: string,
  opts: {
    ca?: string | Buffer | Array<string | Buffer>;
    nowMs?: number;
  } = {},
): crypto.X509Certificate {
  if (certDers.length === 0) {
    throw new TlsProtocolError('server sent an empty certificate list', {
      code: 'TLS_CERT_EMPTY',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
    });
  }

  const parsedChain: crypto.X509Certificate[] = [];
  for (const der of certDers) {
    try {
      parsedChain.push(new crypto.X509Certificate(der));
    } catch (err) {
      throw new TlsProtocolError(
        `failed to parse server X.509 certificate: ${err instanceof Error ? err.message : String(err)}`,
        { code: 'TLS_CERT_PARSE_ERROR', alertDescription: TLS_ALERT_BAD_CERTIFICATE, cause: err },
      );
    }
  }

  const nowMs = opts.nowMs ?? Date.now();
  const leaf = parsedChain[0];
  const intermediates = parsedChain.slice(1);
  const trustAnchors = getTrustAnchors(opts.ca);

  // 1. Leaf validity, EKU, and hostname/IP SAN identity
  checkCertValidityWindow(leaf, nowMs);
  checkServerAuthEku(leaf);

  const cleanHost = stripBrackets(hostname);
  // Require Subject Alternative Name (SAN) extension; reject deprecated CN-only certs (RFC 9525 / WebPKI).
  if (!leaf.subjectAltName || leaf.subjectAltName.trim().length === 0) {
    throw new TlsProtocolError(
      `certificate '${leaf.subject}' is missing a Subject Alternative Name (SAN) extension`,
      { code: 'TLS_CERT_HOSTNAME_MISMATCH', alertDescription: TLS_ALERT_BAD_CERTIFICATE },
    );
  }
  const idErr = tls.checkServerIdentity(cleanHost, leaf.toLegacyObject());
  if (idErr) {
    throw new TlsProtocolError(idErr.message, {
      code: 'TLS_CERT_HOSTNAME_MISMATCH',
      alertDescription: TLS_ALERT_BAD_CERTIFICATE,
      cause: idErr,
    });
  }

  // 2. Direct trust anchor pin (e.g., self-signed cert passed directly via `ca`)
  for (const anchor of trustAnchors) {
    if (anchor.fingerprint256 === leaf.fingerprint256 && anchor.raw.equals(leaf.raw)) {
      checkCertValidityWindow(anchor, nowMs);
      return leaf;
    }
  }

  // 3. Cycle-checked DFS chain building from leaf -> intermediates -> trust anchor (max depth 10)
  // Enforcing RFC 5280 §6.1.4 BasicConstraints cA=TRUE and pathLenConstraint on every CA in path.
  const visited = new Set<string>([leaf.fingerprint256]);
  let lastPathErr: TlsProtocolError | null = null;

  const findChainToAnchor = (
    current: crypto.X509Certificate,
    depth: number,
    nonSelfIssuedIntermediates: number,
  ): boolean => {
    if (depth >= MAX_CERT_CHAIN_DEPTH) {
      return false;
    }

    // Check if any trust anchor directly issued & signed `current`
    for (const anchor of trustAnchors) {
      if (!anchor.ca) {
        continue;
      }
      if (!safeVerifySignature(current, anchor)) {
        continue;
      }
      try {
        checkCertValidityWindow(anchor, nowMs);
        const anchorBc = parseCertBasicConstraints(anchor.raw);
        if (
          anchorBc.pathLenConstraint !== null &&
          nonSelfIssuedIntermediates > anchorBc.pathLenConstraint
        ) {
          throw new TlsProtocolError(
            `trust anchor '${anchor.subject}' BasicConstraints pathLenConstraint=${anchorBc.pathLenConstraint} exceeded by ${nonSelfIssuedIntermediates} intermediate CA(s)`,
            { code: 'TLS_CERT_PATHLEN_EXCEEDED', alertDescription: TLS_ALERT_BAD_CERTIFICATE },
          );
        }
      } catch (err) {
        if (err instanceof TlsProtocolError) lastPathErr = err;
        continue;
      }
      return true;
    }

    // Try server-provided intermediates
    for (const inter of intermediates) {
      if (visited.has(inter.fingerprint256)) {
        continue;
      }
      if (!inter.ca) {
        continue;
      }
      if (!safeVerifySignature(current, inter)) {
        continue;
      }
      let interBc: ParsedCertConstraints;
      try {
        checkCertValidityWindow(inter, nowMs);
        checkServerAuthEku(inter);
        interBc = parseCertBasicConstraints(inter.raw);
        if (!interBc.isCa) {
          throw new TlsProtocolError(
            `intermediate certificate '${inter.subject}' does not assert BasicConstraints cA=TRUE`,
            { code: 'TLS_CERT_INVALID', alertDescription: TLS_ALERT_BAD_CERTIFICATE },
          );
        }
        if (
          interBc.pathLenConstraint !== null &&
          nonSelfIssuedIntermediates > interBc.pathLenConstraint
        ) {
          throw new TlsProtocolError(
            `intermediate CA '${inter.subject}' BasicConstraints pathLenConstraint=${interBc.pathLenConstraint} exceeded by ${nonSelfIssuedIntermediates} sub-CA(s)`,
            { code: 'TLS_CERT_PATHLEN_EXCEEDED', alertDescription: TLS_ALERT_BAD_CERTIFICATE },
          );
        }
      } catch (err) {
        if (err instanceof TlsProtocolError) lastPathErr = err;
        continue;
      }

      visited.add(inter.fingerprint256);
      // RFC 5280 §6.1.4(l): self-issued intermediate certificates do not consume pathLenConstraint.
      const nextNonSelfIssued = interBc.isSelfIssued
        ? nonSelfIssuedIntermediates
        : nonSelfIssuedIntermediates + 1;
      const ok = findChainToAnchor(inter, depth + 1, nextNonSelfIssued);
      if (ok) {
        return true;
      }
      visited.delete(inter.fingerprint256);
    }

    return false;
  };

  if (!findChainToAnchor(leaf, 0, 0)) {
    if (lastPathErr) {
      throw lastPathErr;
    }
    throw new TlsProtocolError(
      `unable to verify certificate chain for '${cleanHost}' against trusted root CAs`,
      { code: 'TLS_CERT_UNTRUSTED', alertDescription: TLS_ALERT_UNKNOWN_CA },
    );
  }

  return leaf;
}

/**
 * Verify TLS 1.3 `CertificateVerify` signature (RFC 8446 §4.4.3).
 */
export function verifyCertificateVerifySignature(
  leafCert: crypto.X509Certificate,
  scheme: number,
  signature: Buffer,
  transcriptHash: Buffer,
): boolean {
  if (!OFFERED_SIGNATURE_SET.has(scheme)) {
    return false;
  }

  const content = Buffer.concat([
    Buffer.alloc(64, 0x20),
    Buffer.from('TLS 1.3, server CertificateVerify\x00', 'ascii'),
    transcriptHash,
  ]);
  const pubKey = leafCert.publicKey;
  const keyType = pubKey.asymmetricKeyType;
  const curve = pubKey.asymmetricKeyDetails?.namedCurve;

  try {
    switch (scheme) {
      case TLS_SIG_ECDSA_SECP256R1_SHA256:
        if (keyType !== 'ec' || curve !== 'prime256v1') return false;
        return crypto.verify('sha256', content, pubKey, signature);

      case TLS_SIG_ECDSA_SECP384R1_SHA384:
        if (keyType !== 'ec' || curve !== 'secp384r1') return false;
        return crypto.verify('sha384', content, pubKey, signature);

      case TLS_SIG_ED25519:
        if (keyType !== 'ed25519') return false;
        return crypto.verify(null, content, pubKey, signature);

      case TLS_SIG_RSA_PSS_RSAE_SHA256:
        if (keyType !== 'rsa') return false;
        return crypto.verify(
          'sha256',
          content,
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
          signature,
        );

      case TLS_SIG_RSA_PSS_RSAE_SHA384:
        if (keyType !== 'rsa') return false;
        return crypto.verify(
          'sha384',
          content,
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
          signature,
        );

      case TLS_SIG_RSA_PSS_RSAE_SHA512:
        if (keyType !== 'rsa') return false;
        return crypto.verify(
          'sha512',
          content,
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 },
          signature,
        );

      case TLS_SIG_RSA_PSS_PSS_SHA256:
        if (keyType !== 'rsa-pss') return false;
        return crypto.verify(
          'sha256',
          content,
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
          signature,
        );

      case TLS_SIG_RSA_PSS_PSS_SHA384:
        if (keyType !== 'rsa-pss') return false;
        return crypto.verify(
          'sha384',
          content,
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
          signature,
        );

      case TLS_SIG_RSA_PSS_PSS_SHA512:
        if (keyType !== 'rsa-pss') return false;
        return crypto.verify(
          'sha512',
          content,
          { key: pubKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 },
          signature,
        );

      default:
        return false;
    }
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// RFC 9849 ECH ClientHello Construction, Padding, AAD, and Confirmation
// ---------------------------------------------------------------------------

function encodeExtension(type: number, data: Buffer): Buffer {
  return Buffer.concat([u16be(type), u16be(data.length), data]);
}

function encodeSniExtension(hostname: string): Buffer {
  const hostBuf = Buffer.from(hostname, 'ascii');
  const entry = Buffer.concat([Buffer.from([0x00]), u16be(hostBuf.length), hostBuf]);
  const body = Buffer.concat([u16be(entry.length), entry]);
  return encodeExtension(TLS_EXT_SERVER_NAME, body);
}

function encodeSupportedVersionsExt(): Buffer {
  // TLS 1.3 (0x0304) ONLY — required by RFC 9849 §5 for ClientHelloInner.
  return encodeExtension(TLS_EXT_SUPPORTED_VERSIONS, Buffer.from([0x02, 0x03, 0x04]));
}

function encodeSupportedGroupsExt(): Buffer {
  return encodeExtension(
    TLS_EXT_SUPPORTED_GROUPS,
    Buffer.concat([u16be(4), u16be(TLS_GROUP_X25519), u16be(TLS_GROUP_SECP256R1)]),
  );
}

function encodeSignatureAlgorithmsExt(): Buffer {
  const body = Buffer.alloc(2 + OFFERED_SIGNATURE_ALGORITHMS.length * 2);
  body.writeUInt16BE(OFFERED_SIGNATURE_ALGORITHMS.length * 2, 0);
  for (let i = 0; i < OFFERED_SIGNATURE_ALGORITHMS.length; i += 1) {
    body.writeUInt16BE(OFFERED_SIGNATURE_ALGORITHMS[i], 2 + i * 2);
  }
  return encodeExtension(TLS_EXT_SIGNATURE_ALGORITHMS, body);
}

function encodeKeyShareExt(share: EphemeralKeyShare): Buffer {
  const entry = Buffer.concat([u16be(share.group), u16be(share.publicKey.length), share.publicKey]);
  return encodeExtension(TLS_EXT_KEY_SHARE, Buffer.concat([u16be(entry.length), entry]));
}

function encodeAlpnExt(protocols: readonly string[]): Buffer {
  const parts: Buffer[] = [];
  for (const proto of protocols) {
    const b = Buffer.from(proto, 'ascii');
    parts.push(Buffer.from([b.length]), b);
  }
  const list = Buffer.concat(parts);
  return encodeExtension(TLS_EXT_ALPN, Buffer.concat([u16be(list.length), list]));
}

function encodeCookieExt(cookie: Buffer): Buffer {
  return encodeExtension(TLS_EXT_COOKIE, Buffer.concat([u16be(cookie.length), cookie]));
}

function buildClientHelloBody(params: {
  random: Buffer;
  legacySessionId: Buffer;
  extensions: readonly Buffer[];
}): Buffer {
  const cipherSuitesBuf = Buffer.alloc(2 + OFFERED_CIPHER_SUITES.length * 2);
  cipherSuitesBuf.writeUInt16BE(OFFERED_CIPHER_SUITES.length * 2, 0);
  for (let i = 0; i < OFFERED_CIPHER_SUITES.length; i += 1) {
    cipherSuitesBuf.writeUInt16BE(OFFERED_CIPHER_SUITES[i], 2 + i * 2);
  }

  const exts = Buffer.concat(params.extensions);
  return Buffer.concat([
    Buffer.from([0x03, 0x03]), // legacy_version = TLS 1.2
    params.random,
    Buffer.from([params.legacySessionId.length]),
    params.legacySessionId,
    cipherSuitesBuf,
    Buffer.from([0x01, 0x00]), // legacy_compression_methods = [null]
    u16be(exts.length),
    exts,
  ]);
}

function wrapHandshakeMessage(hsType: number, body: Buffer): Buffer {
  return Buffer.concat([Buffer.from([hsType & 0xff]), u24be(body.length), body]);
}

function wrapPlaintextRecord(contentType: number, payload: Buffer, legacyVersionMinor = 0x03): Buffer {
  return Buffer.concat([
    Buffer.from([contentType & 0xff, 0x03, legacyVersionMinor & 0xff]),
    u16be(payload.length),
    payload,
  ]);
}

/**
 * Apply RFC 9849 §6.1.3 zero-padding to `EncodedClientHelloInner` (without Handshake header, empty session_id).
 */
export function padEncodedClientHelloInner(
  encodedBody: Buffer,
  maximumNameLength: number,
  innerSniHostname: string | null,
): Buffer {
  const maxLen = maximumNameLength > 0 ? maximumNameLength : 255;
  let namePad: number;
  if (innerSniHostname !== null && innerSniHostname.length > 0) {
    const sniLen = Buffer.byteLength(innerSniHostname, 'ascii');
    namePad = Math.max(0, maxLen - sniLen);
  } else {
    namePad = maxLen + 9;
  }
  const lenSoFar = encodedBody.length + namePad;
  const alignPad = 31 - ((lenSoFar - 1) % 32);
  const totalPad = namePad + alignPad;
  return totalPad > 0 ? Buffer.concat([encodedBody, Buffer.alloc(totalPad)]) : encodedBody;
}

export interface BuiltEchClientHelloPair {
  /** Logical `ClientHelloInner` WITH 4-byte Handshake header & Outer's `legacy_session_id` (for inner transcript). */
  readonly clientHelloInnerMsg: Buffer;
  /** Padded `EncodedClientHelloInner` plaintext sealed by HPKE. */
  readonly encodedClientHelloInner: Buffer;
  /** `ClientHelloOuterAAD` (body WITHOUT 4B Handshake header, `enc` populated, `payload` zeroed). */
  readonly clientHelloOuterAad: Buffer;
  /** Wire `ClientHelloOuter` WITH 4-byte Handshake header (for outer transcript & wire framing). */
  readonly clientHelloOuterMsg: Buffer;
}

/**
 * Construct RFC 9849 `ClientHelloInner`, `EncodedClientHelloInner` (padded), `ClientHelloOuterAAD`,
 * and sealed `ClientHelloOuter` for either the initial flight (`enc` present) or post-HRR (`enc` empty).
 */
export function buildEchClientHelloPair(params: {
  selected: SelectedEchConfig;
  sealer: HpkeSealer;
  /** `enc` for initial ClientHello; empty Buffer for post-HRR ClientHello2. */
  enc: Buffer;
  realHost: string;
  innerRandom: Buffer;
  outerRandom: Buffer;
  legacySessionId: Buffer;
  innerKeyShare: EphemeralKeyShare;
  outerKeyShare: EphemeralKeyShare;
  alpn?: readonly string[];
  cookie?: Buffer;
}): BuiltEchClientHelloPair {
  const { selected, sealer, enc, realHost, innerRandom, outerRandom, legacySessionId } = params;
  const cleanRealHost = stripBrackets(realHost);
  const innerSni = isIpLiteral(cleanRealHost) ? null : cleanRealHost;
  const alpn = params.alpn ?? ['http/1.1'];

  // 1. Build ClientHelloInner extensions (mandatory 0xfe0d = [0x01])
  const innerExts: Buffer[] = [];
  if (innerSni !== null) {
    innerExts.push(encodeSniExtension(innerSni));
  }
  innerExts.push(
    encodeSupportedVersionsExt(),
    encodeSupportedGroupsExt(),
    encodeSignatureAlgorithmsExt(),
    encodeKeyShareExt(params.innerKeyShare),
  );
  if (alpn.length > 0) {
    innerExts.push(encodeAlpnExt(alpn));
  }
  if (params.cookie) {
    innerExts.push(encodeCookieExt(params.cookie));
  }
  innerExts.push(encodeExtension(TLS_EXT_ECH, Buffer.from([ECH_CLIENT_HELLO_INNER])));

  // Logical ClientHelloInner (for inner transcript): HAS Outer's legacy_session_id and 4-byte Handshake header.
  const logicalInnerBody = buildClientHelloBody({
    random: innerRandom,
    legacySessionId,
    extensions: innerExts,
  });
  const clientHelloInnerMsg = wrapHandshakeMessage(TLS_HS_CLIENT_HELLO, logicalInnerBody);

  // EncodedClientHelloInner (for HPKE plaintext): NO 4-byte Handshake header, EMPTY legacy_session_id, §6.1.3 padded.
  const encodedInnerUnpadded = buildClientHelloBody({
    random: innerRandom,
    legacySessionId: Buffer.alloc(0),
    extensions: innerExts,
  });
  const encodedClientHelloInner = padEncodedClientHelloInner(
    encodedInnerUnpadded,
    selected.config.maximumNameLength,
    innerSni,
  );

  const payloadLen = encodedClientHelloInner.length + HPKE_TAG_LEN;

  // 2. Build ClientHelloOuterAAD (WITHOUT 4-byte Handshake header, `enc` present, `payload` zeroed)
  const echOuterExtPrefix = Buffer.concat([
    Buffer.from([ECH_CLIENT_HELLO_OUTER]),
    u16be(selected.suite.kdfId),
    u16be(selected.suite.aeadId),
    Buffer.from([selected.config.configId & 0xff]),
    u16be(enc.length),
    enc,
    u16be(payloadLen),
  ]);
  const echOuterExtPlaceholder = encodeExtension(
    TLS_EXT_ECH,
    Buffer.concat([echOuterExtPrefix, Buffer.alloc(payloadLen)]),
  );

  const outerExts: Buffer[] = [
    encodeSniExtension(selected.config.publicName),
    encodeSupportedVersionsExt(),
    encodeSupportedGroupsExt(),
    encodeSignatureAlgorithmsExt(),
    encodeKeyShareExt(params.outerKeyShare),
  ];
  if (alpn.length > 0) {
    outerExts.push(encodeAlpnExt(alpn));
  }
  if (params.cookie) {
    outerExts.push(encodeCookieExt(params.cookie));
  }
  outerExts.push(echOuterExtPlaceholder);

  const clientHelloOuterAad = buildClientHelloBody({
    random: outerRandom,
    legacySessionId,
    extensions: outerExts,
  });

  // 3. Seal EncodedClientHelloInner with ClientHelloOuterAAD
  const ciphertext = sealer.seal(clientHelloOuterAad, encodedClientHelloInner);
  if (ciphertext.length !== payloadLen) {
    throw new TlsProtocolError(
      `HPKE ciphertext length mismatch: expected ${payloadLen}, got ${ciphertext.length}`,
    );
  }

  // Substitute real ciphertext into the payload slot at the end of ClientHelloOuter body.
  const payloadOffset = clientHelloOuterAad.length - payloadLen;
  const clientHelloOuterBody = Buffer.from(clientHelloOuterAad);
  ciphertext.copy(clientHelloOuterBody, payloadOffset);

  const clientHelloOuterMsg = wrapHandshakeMessage(TLS_HS_CLIENT_HELLO, clientHelloOuterBody);
  return {
    clientHelloInnerMsg,
    encodedClientHelloInner,
    clientHelloOuterAad,
    clientHelloOuterMsg,
  };
}

/**
 * RFC 9849 §7.2 ServerHello ECH acceptance confirmation (8 bytes).
 */
export function computeEchAcceptConfirmation(
  hashAlg: 'sha256' | 'sha384',
  innerRandom: Buffer,
  innerTranscriptPrefix: readonly Buffer[],
  rawServerHelloMsg: Buffer,
): Buffer {
  if (rawServerHelloMsg.length < 38 || rawServerHelloMsg[0] !== TLS_HS_SERVER_HELLO) {
    throw new TlsProtocolError('invalid ServerHello message for ECH confirmation', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  const shZeroed = Buffer.from(rawServerHelloMsg);
  // Zero bytes [30..38]: 4B HS header + 2B version + 24B random prefix = offset 30, last 8B of random.
  shZeroed.fill(0, 30, 38);
  const th = tlsHash(hashAlg, [...innerTranscriptPrefix, shZeroed]);
  const extractSecret = hkdfExtract(hashAlg, Buffer.alloc(0), innerRandom);
  try {
    return hkdfExpandLabel(hashAlg, extractSecret, 'ech accept confirmation', th, 8);
  } finally {
    extractSecret.fill(0);
  }
}

/**
 * RFC 9849 §7.2.1 HelloRetryRequest ECH acceptance confirmation (8 bytes).
 */
export function computeHrrEchAcceptConfirmation(
  hashAlg: 'sha256' | 'sha384',
  innerRandom: Buffer,
  clientHelloInner1Msg: Buffer,
  rawHrrMsg: Buffer,
  hrrEchExtValueOffset: number,
): Buffer {
  const hashLen = hashAlg === 'sha384' ? 48 : 32;
  const ch1Hash = tlsHash(hashAlg, clientHelloInner1Msg);
  const messageHash = Buffer.concat([
    Buffer.from([TLS_HS_MESSAGE_HASH, 0x00, 0x00, hashLen]),
    ch1Hash,
  ]);

  if (hrrEchExtValueOffset < 0 || hrrEchExtValueOffset + 8 > rawHrrMsg.length) {
    throw new TlsProtocolError('HRR ECH extension offset out of range', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  const hrrZeroed = Buffer.from(rawHrrMsg);
  hrrZeroed.fill(0, hrrEchExtValueOffset, hrrEchExtValueOffset + 8);

  const th = tlsHash(hashAlg, [messageHash, hrrZeroed]);
  const extractSecret = hkdfExtract(hashAlg, Buffer.alloc(0), innerRandom);
  try {
    return hkdfExpandLabel(hashAlg, extractSecret, 'hrr ech accept confirmation', th, 8);
  } finally {
    extractSecret.fill(0);
  }
}

// ---------------------------------------------------------------------------
// TLS 1.3 Server Message Parsers
// ---------------------------------------------------------------------------

interface ParsedServerHello {
  readonly isHrr: boolean;
  readonly random: Buffer;
  readonly legacySessionIdEcho: Buffer;
  readonly cipherSuite: number;
  readonly supportedVersion: number | null;
  readonly keyShareGroup: number | null;
  readonly keySharePublicKey: Buffer | null;
  readonly cookie: Buffer | null;
  readonly echExtData: Buffer | null;
  /** Offset of the `0xfe0d` extension's value bytes inside the raw `ServerHello` handshake message. */
  readonly echExtValueOffset: number;
}

function parseServerHello(rawMsg: Buffer): ParsedServerHello {
  if (rawMsg.length < 4 + 2 + 32 + 1 + 2 + 1 + 2) {
    throw new TlsProtocolError('ServerHello truncated', { alertDescription: TLS_ALERT_DECODE_ERROR });
  }
  if (rawMsg[0] !== TLS_HS_SERVER_HELLO) {
    throw new TlsProtocolError(`expected ServerHello (0x02), got 0x${rawMsg[0].toString(16)}`, {
      alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
    });
  }
  let pos = 4;
  const legacyVer = rawMsg.readUInt16BE(pos);
  if (legacyVer !== 0x0303) {
    throw new TlsProtocolError(`unexpected ServerHello legacy_version 0x${legacyVer.toString(16)}`, {
      alertDescription: TLS_ALERT_PROTOCOL_VERSION,
    });
  }
  pos += 2;
  const random = Buffer.from(rawMsg.subarray(pos, pos + 32));
  pos += 32;
  const isHrr = random.equals(TLS_HRR_RANDOM);

  const sidLen = rawMsg[pos];
  pos += 1;
  if (pos + sidLen + 5 > rawMsg.length) {
    throw new TlsProtocolError('ServerHello truncated in session_id', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  const legacySessionIdEcho = Buffer.from(rawMsg.subarray(pos, pos + sidLen));
  pos += sidLen;

  const cipherSuite = rawMsg.readUInt16BE(pos);
  pos += 2;
  const compression = rawMsg[pos];
  pos += 1;
  if (compression !== 0) {
    throw new TlsProtocolError(`non-null compression method ${compression}`, {
      alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
    });
  }

  const extsLen = rawMsg.readUInt16BE(pos);
  pos += 2;
  if (pos + extsLen !== rawMsg.length) {
    throw new TlsProtocolError('ServerHello extensions length mismatch', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }

  const seenExts = new Set<number>();
  let supportedVersion: number | null = null;
  let keyShareGroup: number | null = null;
  let keySharePublicKey: Buffer | null = null;
  let cookie: Buffer | null = null;
  let echExtData: Buffer | null = null;
  let echExtValueOffset = -1;

  while (pos < rawMsg.length) {
    if (pos + 4 > rawMsg.length) {
      throw new TlsProtocolError('ServerHello truncated extension header', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    const extType = rawMsg.readUInt16BE(pos);
    const extLen = rawMsg.readUInt16BE(pos + 2);
    pos += 4;
    if (pos + extLen > rawMsg.length) {
      throw new TlsProtocolError('ServerHello truncated extension data', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    if (seenExts.has(extType)) {
      throw new TlsProtocolError(`duplicate extension 0x${extType.toString(16)} in ServerHello`, {
        alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
      });
    }
    seenExts.add(extType);
    const valOffset = pos;
    const extData = rawMsg.subarray(pos, pos + extLen);
    pos += extLen;

    // RFC 8446 §4.2 + RFC 9849 §7.2: strictly enforce allowed extension sets:
    // - non-HRR ServerHello: {supported_versions (0x002B), key_share (0x0033)}
    // - HRR:                 {supported_versions (0x002B), key_share (0x0033), cookie (0x002C), ech (0xFE0D)}
    if (extType === TLS_EXT_SUPPORTED_VERSIONS) {
      if (extLen !== 2) {
        throw new TlsProtocolError('invalid supported_versions length in ServerHello', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      supportedVersion = extData.readUInt16BE(0);
    } else if (extType === TLS_EXT_KEY_SHARE) {
      if (isHrr) {
        if (extLen !== 2) {
          throw new TlsProtocolError('invalid key_share length in HRR', {
            alertDescription: TLS_ALERT_DECODE_ERROR,
          });
        }
        keyShareGroup = extData.readUInt16BE(0);
      } else {
        if (extLen < 4) {
          throw new TlsProtocolError('truncated key_share in ServerHello', {
            alertDescription: TLS_ALERT_DECODE_ERROR,
          });
        }
        keyShareGroup = extData.readUInt16BE(0);
        const keyLen = extData.readUInt16BE(2);
        if (4 + keyLen !== extLen) {
          throw new TlsProtocolError('key_share length mismatch in ServerHello', {
            alertDescription: TLS_ALERT_DECODE_ERROR,
          });
        }
        keySharePublicKey = Buffer.from(extData.subarray(4));
      }
    } else if (isHrr && extType === TLS_EXT_COOKIE) {
      if (extLen < 3) {
        throw new TlsProtocolError('invalid cookie extension in HRR', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      const cLen = extData.readUInt16BE(0);
      if (cLen === 0 || 2 + cLen !== extLen) {
        throw new TlsProtocolError('cookie extension length mismatch', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      cookie = Buffer.from(extData.subarray(2));
    } else if (isHrr && extType === TLS_EXT_ECH) {
      echExtData = Buffer.from(extData);
      echExtValueOffset = valOffset;
    } else {
      throw new TlsProtocolError(
        `unexpected extension 0x${extType.toString(16)} in ${isHrr ? 'HelloRetryRequest' : 'ServerHello'}`,
        { alertDescription: TLS_ALERT_UNSUPPORTED_EXTENSION },
      );
    }
  }

  return {
    isHrr,
    random,
    legacySessionIdEcho,
    cipherSuite,
    supportedVersion,
    keyShareGroup,
    keySharePublicKey,
    cookie,
    echExtData,
    echExtValueOffset,
  };
}

interface ParsedEncryptedExtensions {
  readonly alpn: string | null;
  readonly echRetryConfigs: Buffer | null;
  readonly hasEchExt: boolean;
}

function parseEncryptedExtensions(
  body: Buffer,
  offeredAlpn: readonly string[],
  offeredSni: boolean,
): ParsedEncryptedExtensions {
  if (body.length < 2) {
    throw new TlsProtocolError('EncryptedExtensions truncated', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  const extsLen = body.readUInt16BE(0);
  if (2 + extsLen !== body.length) {
    throw new TlsProtocolError('EncryptedExtensions length mismatch', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }

  let pos = 2;
  const seen = new Set<number>();
  let alpn: string | null = null;
  let echRetryConfigs: Buffer | null = null;
  let hasEchExt = false;

  while (pos < body.length) {
    if (pos + 4 > body.length) {
      throw new TlsProtocolError('EncryptedExtensions truncated extension header', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    const extType = body.readUInt16BE(pos);
    const extLen = body.readUInt16BE(pos + 2);
    pos += 4;
    if (pos + extLen > body.length) {
      throw new TlsProtocolError('EncryptedExtensions truncated extension data', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    if (seen.has(extType)) {
      throw new TlsProtocolError(`duplicate extension 0x${extType.toString(16)} in EncryptedExtensions`, {
        alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
      });
    }
    seen.add(extType);
    const extData = body.subarray(pos, pos + extLen);
    pos += extLen;

    if (extType === TLS_EXT_ALPN) {
      if (offeredAlpn.length === 0) {
        throw new TlsProtocolError('server sent unsolicited ALPN extension', {
          alertDescription: TLS_ALERT_UNSUPPORTED_EXTENSION,
        });
      }
      if (extLen < 4) {
        throw new TlsProtocolError('malformed ALPN extension in EncryptedExtensions', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      const listLen = extData.readUInt16BE(0);
      if (2 + listLen !== extLen) {
        throw new TlsProtocolError('ALPN list length mismatch', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      const protoLen = extData[2];
      if (protoLen === 0 || 3 + protoLen !== extLen) {
        throw new TlsProtocolError('ALPN must select exactly one protocol', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      // Use latin1 (NOT ascii) so high-bit bytes >= 0x80 cannot alias offered ASCII protocol names.
      const selected = extData.subarray(3, 3 + protoLen).toString('latin1');
      if (!offeredAlpn.includes(selected)) {
        throw new TlsProtocolError(`server selected unoffered ALPN protocol '${selected}'`, {
          alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
        });
      }
      alpn = selected;
    } else if (extType === TLS_EXT_ECH) {
      hasEchExt = true;
      echRetryConfigs = Buffer.from(extData);
    } else if (extType === TLS_EXT_SERVER_NAME) {
      if (!offeredSni) {
        throw new TlsProtocolError('server sent unsolicited server_name extension', {
          alertDescription: TLS_ALERT_UNSUPPORTED_EXTENSION,
        });
      }
      if (extLen !== 0) {
        throw new TlsProtocolError('non-empty server_name in EncryptedExtensions', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
    } else if (extType === TLS_EXT_SUPPORTED_GROUPS) {
      // Allowed by RFC 8446 §4.2.7 in EncryptedExtensions; validate non-empty even list length.
      if (extLen < 4) {
        throw new TlsProtocolError('malformed supported_groups in EncryptedExtensions', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      const groupsLen = extData.readUInt16BE(0);
      if (groupsLen === 0 || groupsLen % 2 !== 0 || groupsLen + 2 !== extLen) {
        throw new TlsProtocolError('malformed supported_groups in EncryptedExtensions', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
    } else {
      throw new TlsProtocolError(
        `unexpected extension 0x${extType.toString(16)} in EncryptedExtensions`,
        { alertDescription: TLS_ALERT_UNSUPPORTED_EXTENSION },
      );
    }
  }

  return { alpn, echRetryConfigs, hasEchExt };
}

function parseCertificateMessage(body: Buffer): Buffer[] {
  if (body.length < 4) {
    throw new TlsProtocolError('Certificate message truncated', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  const reqCtxLen = body[0];
  if (reqCtxLen !== 0) {
    throw new TlsProtocolError('non-empty certificate_request_context in server Certificate', {
      alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
    });
  }
  const listLen = readU24BE(body, 1);
  if (4 + listLen !== body.length) {
    throw new TlsProtocolError('Certificate list length mismatch', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }

  const certs: Buffer[] = [];
  let pos = 4;
  while (pos < body.length) {
    if (pos + 3 > body.length) {
      throw new TlsProtocolError('Certificate entry truncated', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    const certLen = readU24BE(body, pos);
    pos += 3;
    if (certLen === 0 || pos + certLen + 2 > body.length) {
      throw new TlsProtocolError('Certificate entry length invalid or truncated', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    certs.push(Buffer.from(body.subarray(pos, pos + certLen)));
    pos += certLen;
    const extLen = body.readUInt16BE(pos);
    pos += 2;
    if (pos + extLen > body.length) {
      throw new TlsProtocolError('Certificate entry extensions truncated', {
        alertDescription: TLS_ALERT_DECODE_ERROR,
      });
    }
    pos += extLen;
  }

  if (certs.length === 0) {
    throw new TlsProtocolError('server sent zero certificates', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  return certs;
}

function parseCertificateVerify(body: Buffer): { scheme: number; signature: Buffer } {
  if (body.length < 4) {
    throw new TlsProtocolError('CertificateVerify truncated', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  const scheme = body.readUInt16BE(0);
  const sigLen = body.readUInt16BE(2);
  if (4 + sigLen !== body.length || sigLen === 0) {
    throw new TlsProtocolError('CertificateVerify signature length mismatch', {
      alertDescription: TLS_ALERT_DECODE_ERROR,
    });
  }
  return { scheme, signature: Buffer.from(body.subarray(4)) };
}

// ---------------------------------------------------------------------------
// Async Handshake Record / Message Reader over raw net.Socket
// ---------------------------------------------------------------------------

interface HandshakeMessage {
  readonly type: number;
  readonly body: Buffer;
  /** Complete message bytes including 4-byte Handshake header (`type || u24(len) || body`). */
  readonly raw: Buffer;
}

class HandshakeTransport {
  readonly socket: net.Socket;
  private rawBuf: Buffer = Buffer.alloc(0);
  private hsBuf: Buffer = Buffer.alloc(0);
  private readCipher: Tls13RecordCipher | null = null;
  private writeCipher: Tls13RecordCipher | null = null;
  private ignoredCcsCount = 0;
  private ended = false;
  private fatalErr: Error | null = null;
  private wake: (() => void) | null = null;
  private readonly deadlineMs: number;
  private readonly signal?: AbortSignal;

  private readonly onData: (chunk: Buffer) => void;
  private readonly onEnd: () => void;
  private readonly onError: (err: Error) => void;
  private readonly onClose: () => void;
  private readonly onAbort: () => void;

  constructor(socket: net.Socket, timeoutMs: number, signal?: AbortSignal) {
    this.socket = socket;
    this.deadlineMs = Date.now() + timeoutMs;
    this.signal = signal;

    this.onData = (chunk: Buffer): void => {
      this.rawBuf = this.rawBuf.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.rawBuf, chunk]);
      this.notify();
    };
    this.onEnd = (): void => {
      this.ended = true;
      this.notify();
    };
    this.onError = (err: Error): void => {
      this.fatalErr = err;
      this.notify();
    };
    this.onClose = (): void => {
      this.ended = true;
      this.notify();
    };
    this.onAbort = (): void => {
      this.fatalErr = new NerutonError('TLS 1.3 ECH handshake aborted', 'ABORTED');
      this.notify();
    };

    this.socket.on('data', this.onData);
    this.socket.on('end', this.onEnd);
    this.socket.on('error', this.onError);
    this.socket.on('close', this.onClose);
    if (this.signal) {
      if (this.signal.aborted) {
        this.fatalErr = new NerutonError('TLS 1.3 ECH handshake aborted', 'ABORTED');
      } else {
        this.signal.addEventListener('abort', this.onAbort, { once: true });
      }
    }
    this.socket.resume();
  }

  setReadCipher(cipher: Tls13RecordCipher): void {
    // RFC 8446 §5.1: Handshake messages MUST NOT span key changes.
    if (this.hsBuf.length > 0) {
      throw new TlsProtocolError('unconsumed handshake bytes across key change boundary', {
        alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
      });
    }
    this.readCipher = cipher;
  }

  setWriteCipher(cipher: Tls13RecordCipher): void {
    this.writeCipher = cipher;
  }

  hasPendingHandshakeBytes(): boolean {
    return this.hsBuf.length > 0;
  }

  detachForDuplex(): Buffer {
    this.socket.pause();
    this.cleanupListeners();
    const leftover = this.rawBuf;
    this.rawBuf = Buffer.alloc(0);
    return leftover;
  }

  cleanupListeners(): void {
    this.socket.off('data', this.onData);
    this.socket.off('end', this.onEnd);
    this.socket.off('error', this.onError);
    this.socket.off('close', this.onClose);
    if (this.signal) {
      this.signal.removeEventListener('abort', this.onAbort);
    }
    this.wake = null;
  }

  private notify(): void {
    const fn = this.wake;
    this.wake = null;
    fn?.();
  }

  private waitForData(): Promise<void> {
    if (this.fatalErr) {
      return Promise.reject(this.fatalErr);
    }
    if (this.ended) {
      return Promise.reject(new TlsProtocolError('unexpected EOF during TLS 1.3 ECH handshake'));
    }
    const remaining = this.deadlineMs - Date.now();
    if (remaining <= 0) {
      return Promise.reject(new TlsProtocolError('TLS 1.3 ECH handshake timed out', { code: 'TLS_TIMEOUT' }));
    }

    return new Promise<void>((resolve, reject) => {
      let done = false;
      const timer = setTimeout(() => {
        if (done) return;
        done = true;
        this.wake = null;
        reject(new TlsProtocolError('TLS 1.3 ECH handshake timed out', { code: 'TLS_TIMEOUT' }));
      }, remaining);
      timer.unref?.();

      this.wake = () => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (this.fatalErr) {
          reject(this.fatalErr);
        } else {
          resolve();
        }
      };
    });
  }

  async writeRaw(buf: Buffer): Promise<void> {
    if (this.fatalErr) {
      throw this.fatalErr;
    }
    if (this.socket.destroyed) {
      throw new TlsProtocolError('socket destroyed during handshake write');
    }
    await new Promise<void>((resolve, reject) => {
      this.socket.write(buf, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async sendAlertAndClose(description: number, level = TLS_ALERT_FATAL): Promise<void> {
    const alertPayload = Buffer.from([level & 0xff, description & 0xff]);
    let record: Buffer;
    try {
      record = this.writeCipher
        ? this.writeCipher.encryptRecord(TLS_CONTENT_ALERT, alertPayload)
        : wrapPlaintextRecord(TLS_CONTENT_ALERT, alertPayload, 0x03);
    } catch {
      record = wrapPlaintextRecord(TLS_CONTENT_ALERT, alertPayload, 0x03);
    }

    this.socket.on('error', () => {});
    this.cleanupListeners();

    if (!this.socket.destroyed && this.socket.writable) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 200);
        timer.unref?.();
        try {
          this.socket.write(record, () => {
            clearTimeout(timer);
            resolve();
          });
        } catch {
          clearTimeout(timer);
          resolve();
        }
      });
    }
    if (!this.socket.destroyed) {
      this.socket.destroy();
    }
  }

  private async readNextTlsRecord(): Promise<{ contentType: number; header: Buffer; payload: Buffer }> {
    while (this.rawBuf.length < 5) {
      await this.waitForData();
    }
    const contentType = this.rawBuf[0];
    const recordLen = this.rawBuf.readUInt16BE(3);
    const maxLen = this.readCipher ? TLS_MAX_CIPHERTEXT : TLS_MAX_PLAINTEXT;
    if (recordLen > maxLen) {
      throw new TlsProtocolError(`TLS record length ${recordLen} exceeds limit ${maxLen}`, {
        alertDescription: TLS_ALERT_RECORD_OVERFLOW,
      });
    }
    const total = 5 + recordLen;
    while (this.rawBuf.length < total) {
      await this.waitForData();
    }
    const header = Buffer.from(this.rawBuf.subarray(0, 5));
    const payload = Buffer.from(this.rawBuf.subarray(5, total));
    this.rawBuf = this.rawBuf.subarray(total);
    return { contentType, header, payload };
  }

  async readHandshakeMessage(): Promise<HandshakeMessage> {
    while (true) {
      if (this.hsBuf.length >= 4) {
        const hsType = this.hsBuf[0];
        const bodyLen = readU24BE(this.hsBuf, 1);
        if (bodyLen > 256 * 1024) {
          throw new TlsProtocolError(`handshake message too large (${bodyLen} bytes)`, {
            alertDescription: TLS_ALERT_DECODE_ERROR,
          });
        }
        const total = 4 + bodyLen;
        if (this.hsBuf.length >= total) {
          const raw = Buffer.from(this.hsBuf.subarray(0, total));
          const body = Buffer.from(raw.subarray(4));
          this.hsBuf = this.hsBuf.subarray(total);
          return { type: hsType, body, raw };
        }
      }

      const rec = await this.readNextTlsRecord();

      // Ignore middlebox compatibility ChangeCipherSpec (0x14) between handshake messages (RFC 8446 §5),
      // bounded to prevent unbounded CCS flood DoS.
      if (rec.contentType === TLS_CONTENT_CHANGE_CIPHER_SPEC) {
        if (rec.payload.length !== 1 || rec.payload[0] !== 0x01 || this.hsBuf.length > 0) {
          throw new TlsProtocolError('invalid or interleaved ChangeCipherSpec record', {
            alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
          });
        }
        this.ignoredCcsCount += 1;
        if (this.ignoredCcsCount > MAX_IGNORED_CCS) {
          throw new TlsProtocolError(
            `too many ChangeCipherSpec records during handshake (limit ${MAX_IGNORED_CCS})`,
            { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
          );
        }
        continue;
      }

      if (rec.contentType === TLS_CONTENT_ALERT) {
        if (this.readCipher !== null) {
          throw new TlsProtocolError('unencrypted TLS alert received after ServerHello key change', {
            alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
          });
        }
        if (rec.payload.length !== 2) {
          throw new TlsProtocolError('malformed plaintext TLS alert', {
            alertDescription: TLS_ALERT_DECODE_ERROR,
          });
        }
        const [level, desc] = rec.payload;
        throw new TlsProtocolError(`peer sent TLS alert (level=${level}, description=${desc})`, {
          code: 'TLS_PEER_ALERT',
          alertDescription: desc,
        });
      }

      if (this.readCipher === null) {
        if (rec.contentType !== TLS_CONTENT_HANDSHAKE) {
          throw new TlsProtocolError(
            `expected plaintext Handshake record (0x16), got 0x${rec.contentType.toString(16)}`,
            { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
          );
        }
        // RFC 8446 §5.1: zero-length Handshake fragments are forbidden.
        if (rec.payload.length === 0) {
          throw new TlsProtocolError('empty plaintext Handshake record fragment', {
            alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
          });
        }
        this.hsBuf = this.hsBuf.length === 0 ? rec.payload : Buffer.concat([this.hsBuf, rec.payload]);
      } else {
        if (rec.contentType !== TLS_CONTENT_APPLICATION_DATA) {
          throw new TlsProtocolError(
            `expected encrypted ApplicationData record (0x17), got 0x${rec.contentType.toString(16)}`,
            { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
          );
        }
        const dec = this.readCipher.decryptRecord(rec.header, rec.payload);
        if (dec.contentType === TLS_CONTENT_ALERT) {
          if (dec.content.length !== 2) {
            throw new TlsProtocolError('malformed encrypted TLS alert', {
              alertDescription: TLS_ALERT_DECODE_ERROR,
            });
          }
          const [level, desc] = dec.content;
          throw new TlsProtocolError(`peer sent encrypted TLS alert (level=${level}, description=${desc})`, {
            code: 'TLS_PEER_ALERT',
            alertDescription: desc,
          });
        }
        if (dec.contentType !== TLS_CONTENT_HANDSHAKE) {
          throw new TlsProtocolError(
            `unexpected inner record type 0x${dec.contentType.toString(16)} during handshake`,
            { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
          );
        }
        if (dec.content.length === 0) {
          throw new TlsProtocolError('empty encrypted Handshake record fragment', {
            alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
          });
        }
        this.hsBuf = this.hsBuf.length === 0 ? dec.content : Buffer.concat([this.hsBuf, dec.content]);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Authenticated TLS 1.3 + ECH `stream.Duplex` (`Tls13EchDuplex`)
// ---------------------------------------------------------------------------

export interface Tls13EchDuplexInit {
  readonly raw: net.Socket;
  readonly clientCipher: Tls13RecordCipher;
  readonly serverCipher: Tls13RecordCipher;
  readonly leftoverBytes: Buffer;
  readonly leafCert: crypto.X509Certificate;
  readonly authorized: boolean;
  readonly alpnProtocol: string | false;
  readonly outerSni: string;
  readonly realHost: string;
  readonly cipherSuite: CipherSuiteSpec;
  readonly echRetried: boolean;
}

/**
 * Pure-TypeScript TLS 1.3 + ECH `stream.Duplex` plugging directly into `ws` (`createConnection`)
 * or raw Node HTTPS requests with full AEAD record framing, backpressure, KeyUpdate,
 * NewSessionTicket handling, and safe teardown.
 */
export class Tls13EchDuplex extends Duplex {
  readonly raw: net.Socket;
  readonly encrypted = true;
  readonly connecting = false;
  readonly authorized: boolean;
  readonly authorizationError: Error | null = null;
  readonly alpnProtocol: string | false;
  readonly outerSni: string;
  readonly realHost: string;
  readonly echStatus = 'accepted' as const;
  readonly echRetried: boolean;
  readonly cipherSuite: CipherSuiteSpec;

  private readonly clientCipher: Tls13RecordCipher;
  private readonly serverCipher: Tls13RecordCipher;
  private readonly leafCert: crypto.X509Certificate;

  private rawBuf: Buffer;
  private postHsBuf: Buffer = Buffer.alloc(0);
  private readPaused = false;
  private eofPushed = false;
  private rawEnded = false;
  private rawClosed = false;
  private closeNotifySent = false;
  private drainCleanup: (() => void) | undefined;

  private readonly onRawData: (chunk: Buffer) => void;
  private readonly onRawEnd: () => void;
  private readonly onRawError: (err: Error) => void;
  private readonly onRawClose: () => void;
  private readonly onRawTimeout: () => void;

  constructor(init: Tls13EchDuplexInit) {
    super({ allowHalfOpen: true });
    this.raw = init.raw;
    this.clientCipher = init.clientCipher;
    this.serverCipher = init.serverCipher;
    this.leafCert = init.leafCert;
    this.authorized = init.authorized;
    this.alpnProtocol = init.alpnProtocol;
    this.outerSni = init.outerSni;
    this.realHost = init.realHost;
    this.cipherSuite = init.cipherSuite;
    this.echRetried = init.echRetried;
    this.rawBuf = init.leftoverBytes.length > 0 ? Buffer.from(init.leftoverBytes) : Buffer.alloc(0);
    this.rawEnded = init.raw.readableEnded;
    this.rawClosed = init.raw.destroyed;

    this.onRawData = (chunk: Buffer): void => {
      if (this.destroyed || this.eofPushed) return;
      this.rawBuf = this.rawBuf.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.rawBuf, chunk]);
      this.processIncomingRecords();
    };

    this.onRawEnd = (): void => {
      this.rawEnded = true;
      if (this.destroyed) return;
      this.processIncomingRecords();
      this.maybeFinalizeEof();
    };

    this.onRawError = (err: Error): void => {
      if (!this.destroyed) {
        this.destroy(err);
      }
    };

    this.onRawClose = (): void => {
      this.rawClosed = true;
      this.rawEnded = true;
      if (this.destroyed) return;
      this.processIncomingRecords();
      this.maybeFinalizeEof();
      // Only tear down the Duplex once EOF has been delivered AND drained by the consumer;
      // never wipe unread `rawBuf` or `readableBuffer` while backpressure is active!
      if (!this.destroyed && this.readableEnded) {
        this.destroy();
      }
    };

    this.onRawTimeout = (): void => {
      this.emit('timeout');
    };

    this.once('end', () => {
      if (this.rawClosed && !this.destroyed) {
        this.destroy();
      }
    });

    this.raw.on('data', this.onRawData);
    this.raw.on('end', this.onRawEnd);
    this.raw.on('error', this.onRawError);
    this.raw.on('close', this.onRawClose);
    this.raw.on('timeout', this.onRawTimeout);
  }

  /**
   * Finalize readable EOF after the underlying TCP stream has ended/closed, ONLY once backpressure
   * has cleared (`!this.readPaused`) and all complete buffered TLS records have been decrypted.
   * Rejects truncated TLS records or partial post-handshake messages at EOF instead of silently truncating.
   */
  private maybeFinalizeEof(): void {
    if (this.destroyed || this.eofPushed || this.readPaused) {
      return;
    }
    if (!this.rawEnded && !this.rawClosed) {
      return;
    }
    if (this.rawBuf.length > 0 || this.postHsBuf.length > 0) {
      this.destroy(
        new TlsProtocolError(
          this.rawBuf.length > 0
            ? 'unexpected EOF with truncated TLS record buffered'
            : 'unexpected EOF with partial post-handshake message buffered',
          { alertDescription: TLS_ALERT_DECODE_ERROR },
        ),
      );
      return;
    }
    this.eofPushed = true;
    this.push(null);
  }

  getProtocol(): string {
    return 'TLSv1.3';
  }

  getCipher(): { name: string; version: string } {
    return { name: this.cipherSuite.name, version: 'TLSv1.3' };
  }

  getPeerCertificate(): tls.PeerCertificate {
    return this.leafCert.toLegacyObject();
  }

  get remoteAddress(): string | undefined {
    return this.raw.remoteAddress;
  }

  get remotePort(): number | undefined {
    return this.raw.remotePort;
  }

  get remoteFamily(): string | undefined {
    return this.raw.remoteFamily;
  }

  get localAddress(): string | undefined {
    return this.raw.localAddress;
  }

  get localPort(): number | undefined {
    return this.raw.localPort;
  }

  address(): net.AddressInfo | Record<string, never> {
    return this.raw.address();
  }

  setNoDelay(noDelay = true): this {
    try {
      this.raw.setNoDelay(noDelay);
    } catch {
      // Ignore if not supported on wrapped stream.
    }
    return this;
  }

  setKeepAlive(enable = false, initialDelay = 0): this {
    try {
      this.raw.setKeepAlive(enable, initialDelay);
    } catch {
      // Ignore.
    }
    return this;
  }

  setTimeout(timeout: number, callback?: () => void): this {
    if (callback) {
      this.once('timeout', callback);
    }
    this.raw.setTimeout(timeout);
    return this;
  }

  ref(): this {
    this.raw.ref();
    return this;
  }

  unref(): this {
    this.raw.unref();
    return this;
  }

  private sendEncryptedAlertBestEffort(level: number, description: number): void {
    if (this.raw.destroyed || !this.raw.writable) return;
    if (description === TLS_ALERT_CLOSE_NOTIFY) {
      if (this.closeNotifySent) return;
      this.closeNotifySent = true;
    }
    try {
      const rec = this.clientCipher.encryptRecord(
        TLS_CONTENT_ALERT,
        Buffer.from([level & 0xff, description & 0xff]),
      );
      this.raw.write(rec);
    } catch {
      // Best effort during teardown.
    }
  }

  private handlePostHandshakeBytes(data: Buffer): void {
    // RFC 8446 §5.1: zero-length Handshake fragments are forbidden.
    if (data.length === 0) {
      this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
      this.destroy(
        new TlsProtocolError('empty post-handshake Handshake record fragment', {
          alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
        }),
      );
      return;
    }

    this.postHsBuf = this.postHsBuf.length === 0 ? data : Buffer.concat([this.postHsBuf, data]);

    while (!this.destroyed && this.postHsBuf.length >= 4) {
      const hsType = this.postHsBuf[0];
      const bodyLen = readU24BE(this.postHsBuf, 1);
      const total = 4 + bodyLen;
      if (bodyLen > 64 * 1024) {
        this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_DECODE_ERROR);
        this.destroy(
          new TlsProtocolError(`post-handshake message too large (${bodyLen} bytes)`, {
            alertDescription: TLS_ALERT_DECODE_ERROR,
          }),
        );
        return;
      }
      if (this.postHsBuf.length < total) {
        return;
      }
      const body = this.postHsBuf.subarray(4, total);
      this.postHsBuf = this.postHsBuf.subarray(total);

      if (hsType === TLS_HS_NEW_SESSION_TICKET) {
        // RFC 8446 §4.6.1: safely ignore post-handshake session tickets.
        continue;
      }

      if (hsType === TLS_HS_KEY_UPDATE) {
        if (body.length !== 1 || (body[0] !== 0 && body[0] !== 1)) {
          this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
          this.destroy(
            new TlsProtocolError('invalid KeyUpdate request_update value', {
              alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
            }),
          );
          return;
        }
        // RFC 8446 §5.1: KeyUpdate MUST align with a record boundary (no coalesced trailing bytes across key change).
        if (this.postHsBuf.length > 0) {
          this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
          this.destroy(
            new TlsProtocolError('unconsumed post-handshake bytes across KeyUpdate key change boundary', {
              alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
            }),
          );
          return;
        }
        const updateRequested = body[0] === 1;
        try {
          // RFC 8446 §4.6.3: update server read key immediately for all subsequent records.
          this.serverCipher.rotateKeys();

          if (updateRequested) {
            // Send KeyUpdate(update_not_requested=0) under CURRENT client key, then rotate client key.
            const replyMsg = wrapHandshakeMessage(TLS_HS_KEY_UPDATE, Buffer.from([0x00]));
            const replyRec = this.clientCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, replyMsg);
            this.clientCipher.rotateKeys();
            if (!this.raw.destroyed && this.raw.writable) {
              this.raw.write(replyRec);
            }
          }
        } catch (err) {
          this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_INTERNAL_ERROR);
          this.destroy(err instanceof Error ? err : new Error(String(err)));
          return;
        }
        continue;
      }

      this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
      this.destroy(
        new TlsProtocolError(
          `unexpected post-handshake message type 0x${hsType.toString(16)}`,
          { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
        ),
      );
      return;
    }
  }

  private processIncomingRecords(): void {
    if (this.destroyed || this.eofPushed || this.readPaused) {
      return;
    }
    while (!this.destroyed && !this.eofPushed && !this.readPaused && this.rawBuf.length >= 5) {
      const contentType = this.rawBuf[0];
      const recordLen = this.rawBuf.readUInt16BE(3);
      if (recordLen > TLS_MAX_CIPHERTEXT) {
        this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_RECORD_OVERFLOW);
        this.destroy(
          new TlsProtocolError(`TLS record exceeds ${TLS_MAX_CIPHERTEXT} bytes`, {
            alertDescription: TLS_ALERT_RECORD_OVERFLOW,
          }),
        );
        return;
      }
      const total = 5 + recordLen;
      if (this.rawBuf.length < total) {
        break;
      }

      const header = Buffer.from(this.rawBuf.subarray(0, 5));
      const payload = Buffer.from(this.rawBuf.subarray(5, total));
      this.rawBuf = this.rawBuf.subarray(total);

      // RFC 8446 §5 / §6: post-handshake records MUST be encrypted ApplicationData (0x17).
      // Rejecting unencrypted Alert (0x15) prevents TLS 1.3 truncation attacks; rejecting post-handshake CCS (0x14) is required by §5.
      if (contentType !== TLS_CONTENT_APPLICATION_DATA) {
        this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        this.destroy(
          new TlsProtocolError(
            `unexpected unencrypted TLS record type 0x${contentType.toString(16)} after handshake`,
            { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
          ),
        );
        return;
      }

      let dec: { contentType: number; content: Buffer };
      try {
        dec = this.serverCipher.decryptRecord(header, payload);
      } catch (err) {
        const alertDesc =
          err instanceof TlsProtocolError && err.alertDescription !== undefined
            ? err.alertDescription
            : TLS_ALERT_BAD_RECORD_MAC;
        this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, alertDesc);
        this.destroy(err instanceof Error ? err : new Error(String(err)));
        return;
      }

      if (dec.contentType === TLS_CONTENT_APPLICATION_DATA) {
        // RFC 8446 §5.1: ApplicationData MUST NOT be interleaved with a partial Handshake message.
        if (this.postHsBuf.length > 0) {
          this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
          this.destroy(
            new TlsProtocolError('interleaved ApplicationData while partial post-handshake message is buffered', {
              alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
            }),
          );
          return;
        }
        if (dec.content.length > 0) {
          const canContinue = this.push(dec.content);
          if (this.destroyed || this.eofPushed) {
            return;
          }
          if (!canContinue) {
            this.readPaused = true;
            this.raw.pause();
            return;
          }
        }
      } else if (dec.contentType === TLS_CONTENT_HANDSHAKE) {
        this.handlePostHandshakeBytes(dec.content);
        if (this.destroyed || this.eofPushed) {
          return;
        }
      } else if (dec.contentType === TLS_CONTENT_ALERT) {
        // RFC 8446 §5.1: Alert MUST NOT be interleaved with a partial Handshake message.
        if (this.postHsBuf.length > 0) {
          this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
          this.destroy(
            new TlsProtocolError('interleaved Alert while partial post-handshake message is buffered', {
              alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
            }),
          );
          return;
        }
        if (dec.content.length !== 2) {
          this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_DECODE_ERROR);
          this.destroy(
            new TlsProtocolError('malformed encrypted TLS alert', {
              alertDescription: TLS_ALERT_DECODE_ERROR,
            }),
          );
          return;
        }
        const [level, desc] = dec.content;
        if (level !== TLS_ALERT_WARNING && level !== TLS_ALERT_FATAL) {
          this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_ILLEGAL_PARAMETER);
          this.destroy(
            new TlsProtocolError(`invalid TLS alert level ${level}`, {
              alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
            }),
          );
          return;
        }
        if (desc === TLS_ALERT_CLOSE_NOTIFY) {
          this.eofPushed = true;
          this.push(null);
          return;
        }
        this.destroy(
          new TlsProtocolError(`peer sent TLS alert (level=${level}, description=${desc})`, {
            code: 'TLS_PEER_ALERT',
            alertDescription: desc,
          }),
        );
        return;
      } else {
        this.sendEncryptedAlertBestEffort(TLS_ALERT_FATAL, TLS_ALERT_UNEXPECTED_MESSAGE);
        this.destroy(
          new TlsProtocolError(`unexpected TLS inner content type 0x${dec.contentType.toString(16)}`, {
            alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
          }),
        );
        return;
      }
    }
  }

  override _read(_size: number): void {
    this.readPaused = false;
    this.processIncomingRecords();
    if (!this.readPaused && !this.destroyed && !this.eofPushed) {
      if (this.rawEnded || this.rawClosed || this.raw.readableEnded) {
        this.rawEnded = true;
        this.maybeFinalizeEof();
      } else if (!this.raw.destroyed) {
        this.raw.resume();
      }
    }
  }

  override _write(
    chunk: Buffer | Uint8Array | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    if (this.destroyed || this.raw.destroyed) {
      callback(new Error('TLS 1.3 ECH socket destroyed'));
      return;
    }

    const buf = Buffer.isBuffer(chunk)
      ? chunk
      : typeof chunk === 'string'
        ? Buffer.from(chunk, encoding)
        : Buffer.from(chunk);

    if (buf.length === 0) {
      callback();
      return;
    }

    // Chunk outbound application writes to <= 16384 bytes per TLS 1.3 record.
    const records: Buffer[] = [];
    try {
      for (let off = 0; off < buf.length; off += TLS_MAX_PLAINTEXT) {
        const slice = buf.subarray(off, Math.min(buf.length, off + TLS_MAX_PLAINTEXT));
        records.push(this.clientCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, slice));
      }
    } catch (err) {
      callback(err instanceof Error ? err : new Error(String(err)));
      return;
    }

    const wire = records.length === 1 ? records[0] : Buffer.concat(records);
    const ok = this.raw.write(wire);
    if (ok) {
      callback();
      return;
    }

    const onDrain = (): void => {
      cleanup();
      callback();
    };
    const onError = (err: Error): void => {
      cleanup();
      callback(err);
    };
    const onClose = (): void => {
      cleanup();
      callback(new Error('underlying socket closed before drain'));
    };
    const cleanup = (): void => {
      this.raw.off('drain', onDrain);
      this.raw.off('error', onError);
      this.raw.off('close', onClose);
      if (this.drainCleanup === cleanup) {
        this.drainCleanup = undefined;
      }
    };
    this.drainCleanup = cleanup;
    this.raw.once('drain', onDrain);
    this.raw.once('error', onError);
    this.raw.once('close', onClose);
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.raw.destroyed || this.raw.writableEnded) {
      callback();
      return;
    }
    this.sendEncryptedAlertBestEffort(TLS_ALERT_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    this.raw.end(() => callback());
  }

  override _destroy(err: Error | null, callback: (error?: Error | null) => void): void {
    if (this.drainCleanup) {
      this.drainCleanup();
    }
    if (!err) {
      this.sendEncryptedAlertBestEffort(TLS_ALERT_WARNING, TLS_ALERT_CLOSE_NOTIFY);
    }

    // Attach no-op error listener BEFORE detaching onRawError so destroying `raw` never causes uncaughtException.
    this.raw.on('error', () => {});
    this.raw.off('data', this.onRawData);
    this.raw.off('end', this.onRawEnd);
    this.raw.off('error', this.onRawError);
    this.raw.off('close', this.onRawClose);
    this.raw.off('timeout', this.onRawTimeout);

    if (!this.raw.destroyed) {
      this.raw.destroy();
    }

    this.clientCipher.destroy();
    this.serverCipher.destroy();
    this.rawBuf = Buffer.alloc(0);
    this.postHsBuf = Buffer.alloc(0);
    callback(err);
  }
}

// ---------------------------------------------------------------------------
// Complete TLS 1.3 + RFC 9849 ECH Handshake Driver
// ---------------------------------------------------------------------------

export interface Tls13EchHandshakeOptions {
  /** Real destination hostname (placed inside encrypted `ClientHelloInner` and verified against server cert). */
  readonly realHost: string;
  /** Wire `ECHConfigList` (or array of lists from DoH HTTPS records). */
  readonly echConfigList: Buffer | readonly Buffer[];
  /** Disable X.509 CA chain & hostname trust checks (still verifies CertificateVerify & Finished). */
  readonly noTlsVerify?: boolean;
  /** Custom CA certificate(s) overriding default `tls.rootCertificates`. */
  readonly ca?: string | Buffer | Array<string | Buffer>;
  /** Offered ALPN protocol list (default: `['http/1.1']`). */
  readonly alpn?: readonly string[];
  /** Handshake timeout in ms (default: `10000`). */
  readonly timeoutMs?: number;
  /** Optional `AbortSignal`. */
  readonly signal?: AbortSignal;
  /** Internal flag marking whether this handshake is a post-rejection `retry_configs` retry. */
  readonly isRetry?: boolean;
}

/**
 * Perform a full RFC 8446 TLS 1.3 + RFC 9849 ECH handshake on an already-connected `net.Socket`.
 *
 * - On ECH acceptance: returns an authenticated `Tls13EchDuplex`.
 * - On ECH rejection: strictly authenticates the outer certificate for `public_name`, verifies
 *   `CertificateVerify` and server `Finished`, sends fatal alert `ech_required (0x79)`, destroys
 *   the TCP socket with ZERO application data sent, and throws `EchRejectedError` containing any
 *   authenticated `retry_configs` for a 1-shot retry on a fresh TCP socket.
 */
export async function performTls13EchHandshake(
  socket: net.Socket,
  opts: Tls13EchHandshakeOptions,
): Promise<Tls13EchDuplex> {
  const selected = selectEchConfig(opts.echConfigList);
  if (!selected) {
    throw new NerutonError(
      'no compatible ECHConfig found in ECHConfigList for supported HPKE suites',
      'ECH_INVALID_CONFIG',
    );
  }

  const offeredAlpn = opts.alpn ?? ['http/1.1'];
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const transport = new HandshakeTransport(socket, timeoutMs, opts.signal);

  // Set up RFC 9180 HPKE Base-mode sender context (RFC 9849 §6.1: info = "tls ech\0" || ECHConfig)
  const hpkeInfo = Buffer.concat([Buffer.from('tls ech\0', 'ascii'), selected.config.rawConfig]);
  const hpkeSetup = setupBaseS(selected.suite, selected.config.publicKey, hpkeInfo);
  hpkeSetup.sharedSecret.fill(0);
  hpkeSetup.key.fill(0);
  hpkeSetup.baseNonce.fill(0);
  hpkeSetup.exporterSecret.fill(0);
  const sealer = hpkeSetup.sealer;

  let clientHsCipher: Tls13RecordCipher | null = null;
  let serverHsCipher: Tls13RecordCipher | null = null;

  try {
    const innerRandom = crypto.randomBytes(32);
    const outerRandom = crypto.randomBytes(32);
    // Middlebox compatibility: 32-byte legacy_session_id (identical on Outer & logical Inner; empty on EncodedInner).
    const legacySessionId = crypto.randomBytes(32);

    let currentGroup = TLS_GROUP_X25519;
    let innerKeyShare = generateKeyShare(currentGroup);
    let outerKeyShare = generateKeyShare(currentGroup);

    const ch1 = buildEchClientHelloPair({
      selected,
      sealer,
      enc: hpkeSetup.enc,
      realHost: opts.realHost,
      innerRandom,
      outerRandom,
      legacySessionId,
      innerKeyShare,
      outerKeyShare,
      alpn: offeredAlpn,
    });

    const outerTranscript: Buffer[] = [ch1.clientHelloOuterMsg];
    const innerTranscript: Buffer[] = [ch1.clientHelloInnerMsg];

    // Send initial ClientHelloOuter (legacy record version 0x0301 per RFC 8446 §5.1)
    await transport.writeRaw(wrapPlaintextRecord(TLS_CONTENT_HANDSHAKE, ch1.clientHelloOuterMsg, 0x01));

    // Read ServerHello (or HelloRetryRequest)
    let shHs = await transport.readHandshakeMessage();
    let sh = parseServerHello(shHs.raw);

    if (!sh.legacySessionIdEcho.equals(legacySessionId)) {
      throw new TlsProtocolError('ServerHello legacy_session_id_echo mismatch', {
        alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
      });
    }
    if (sh.supportedVersion !== 0x0304) {
      throw new TlsProtocolError('server did not negotiate TLS 1.3 (0x0304)', {
        alertDescription: TLS_ALERT_PROTOCOL_VERSION,
      });
    }
    const suite = getCipherSuiteSpec(sh.cipherSuite);
    if (!suite) {
      throw new TlsProtocolError(
        `server selected unsupported TLS 1.3 cipher suite 0x${sh.cipherSuite.toString(16)}`,
        { alertDescription: TLS_ALERT_ILLEGAL_PARAMETER },
      );
    }

    let hrrEchAccepted = false;
    let hrrEchRejected = false;

    if (sh.isHrr) {
      // RFC 8446 §5.1: HelloRetryRequest MUST NOT have trailing handshake bytes coalesced in the same record.
      if (transport.hasPendingHandshakeBytes()) {
        throw new TlsProtocolError('unconsumed handshake bytes after HelloRetryRequest', {
          alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
        });
      }

      // RFC 9849 §7.2.1 HelloRetryRequest ECH handling
      if (sh.echExtData !== null) {
        if (sh.echExtData.length !== 8) {
          throw new TlsProtocolError(
            `HRR encrypted_client_hello extension must be 8 bytes (got ${sh.echExtData.length})`,
            { alertDescription: TLS_ALERT_DECODE_ERROR },
          );
        }
        const expectedHrrConfirm = computeHrrEchAcceptConfirmation(
          suite.hashAlg,
          innerRandom,
          ch1.clientHelloInnerMsg,
          shHs.raw,
          sh.echExtValueOffset,
        );
        if (crypto.timingSafeEqual(sh.echExtData, expectedHrrConfirm)) {
          hrrEchAccepted = true;
        } else {
          hrrEchRejected = true;
        }
      } else {
        hrrEchRejected = true;
      }

      // Check HRR key_share group / cookie validity (RFC 8446 §4.1.4 & §4.2.8)
      let nextGroup = currentGroup;
      if (sh.keyShareGroup !== null) {
        if (sh.keyShareGroup !== TLS_GROUP_X25519 && sh.keyShareGroup !== TLS_GROUP_SECP256R1) {
          throw new TlsProtocolError(
            `HRR requested unsupported key_share group 0x${sh.keyShareGroup.toString(16)}`,
            { alertDescription: TLS_ALERT_ILLEGAL_PARAMETER },
          );
        }
        if (sh.keyShareGroup === currentGroup) {
          throw new TlsProtocolError('HRR requested key_share group already sent in initial ClientHello', {
            alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
          });
        }
        nextGroup = sh.keyShareGroup;
      } else if (!sh.cookie) {
        throw new TlsProtocolError('HRR requested neither new key_share nor cookie', {
          alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
        });
      }

      // Roll up both transcripts via synthetic message_hash (RFC 8446 §4.4.1)
      const outerMsgHash = Buffer.concat([
        Buffer.from([TLS_HS_MESSAGE_HASH, 0x00, 0x00, suite.hashLen]),
        tlsHash(suite.hashAlg, ch1.clientHelloOuterMsg),
      ]);
      const innerMsgHash = Buffer.concat([
        Buffer.from([TLS_HS_MESSAGE_HASH, 0x00, 0x00, suite.hashLen]),
        tlsHash(suite.hashAlg, ch1.clientHelloInnerMsg),
      ]);

      outerTranscript.length = 0;
      outerTranscript.push(outerMsgHash, shHs.raw);
      innerTranscript.length = 0;
      innerTranscript.push(innerMsgHash, shHs.raw);

      if (nextGroup !== currentGroup) {
        currentGroup = nextGroup;
        innerKeyShare = generateKeyShare(currentGroup);
        outerKeyShare = generateKeyShare(currentGroup);
      }

      // Build ClientHello2: SAME innerRandom, SAME legacySessionId, SAME HPKE sealer (seq=1), enc = empty!
      const ch2 = buildEchClientHelloPair({
        selected,
        sealer,
        enc: Buffer.alloc(0),
        realHost: opts.realHost,
        innerRandom,
        outerRandom,
        legacySessionId,
        innerKeyShare,
        outerKeyShare,
        alpn: offeredAlpn,
        cookie: sh.cookie ?? undefined,
      });

      outerTranscript.push(ch2.clientHelloOuterMsg);
      innerTranscript.push(ch2.clientHelloInnerMsg);

      // Send ClientHelloOuter2
      await transport.writeRaw(wrapPlaintextRecord(TLS_CONTENT_HANDSHAKE, ch2.clientHelloOuterMsg, 0x03));

      // Read actual ServerHello after HRR
      shHs = await transport.readHandshakeMessage();
      sh = parseServerHello(shHs.raw);

      if (sh.isHrr) {
        throw new TlsProtocolError('server sent a second HelloRetryRequest', {
          alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
        });
      }
      if (!sh.legacySessionIdEcho.equals(legacySessionId)) {
        throw new TlsProtocolError('ServerHello legacy_session_id_echo mismatch after HRR', {
          alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
        });
      }
      if (sh.supportedVersion !== 0x0304) {
        throw new TlsProtocolError('ServerHello after HRR did not negotiate TLS 1.3', {
          alertDescription: TLS_ALERT_PROTOCOL_VERSION,
        });
      }
      if (sh.cipherSuite !== suite.id) {
        throw new TlsProtocolError('ServerHello cipher suite changed after HRR', {
          alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
        });
      }
    }

    // RFC 8446 §5.1: ServerHello MUST NOT have trailing plaintext handshake bytes across key change boundary.
    if (transport.hasPendingHandshakeBytes()) {
      throw new TlsProtocolError('unconsumed handshake bytes after ServerHello before key change', {
        alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
      });
    }

    // Non-HRR ServerHello MUST NOT contain 0xfe0d extension (RFC 9849 §7.2)
    if (sh.echExtData !== null) {
      throw new TlsProtocolError('unexpected encrypted_client_hello extension in ServerHello', {
        alertDescription: TLS_ALERT_UNSUPPORTED_EXTENSION,
      });
    }
    if (sh.keyShareGroup === null || sh.keySharePublicKey === null) {
      throw new TlsProtocolError('ServerHello missing key_share extension', {
        alertDescription: TLS_ALERT_MISSING_EXTENSION,
      });
    }
    if (sh.keyShareGroup !== currentGroup) {
      throw new TlsProtocolError(
        `ServerHello key_share group 0x${sh.keyShareGroup.toString(16)} does not match offered 0x${currentGroup.toString(16)}`,
        { alertDescription: TLS_ALERT_ILLEGAL_PARAMETER },
      );
    }

    // RFC 9849 §7.2 ServerHello ECH acceptance confirmation
    let echAccepted = false;
    if (!hrrEchRejected) {
      const expectedShConfirm = computeEchAcceptConfirmation(
        suite.hashAlg,
        innerRandom,
        innerTranscript,
        shHs.raw,
      );
      const actualShConfirm = shHs.raw.subarray(30, 38);
      echAccepted = crypto.timingSafeEqual(actualShConfirm, expectedShConfirm);

      if (hrrEchAccepted && !echAccepted) {
        // RFC 9849 §7.2.1: if HRR confirmed ECH, ServerHello MUST also confirm ECH.
        throw new TlsProtocolError('HRR confirmed ECH acceptance but ServerHello did not', {
          alertDescription: TLS_ALERT_ILLEGAL_PARAMETER,
        });
      }
    }

    // Select active transcript and ephemeral key share based on ECH acceptance
    const activeTranscript: Buffer[] = echAccepted
      ? [...innerTranscript, shHs.raw]
      : [...outerTranscript, shHs.raw];
    const activeKeyShare = echAccepted ? innerKeyShare : outerKeyShare;
    const targetVerifyHost = echAccepted ? opts.realHost : selected.config.publicName;

    // Derive TLS 1.3 handshake keys (RFC 8446 §7.1)
    const zeroHash = Buffer.alloc(suite.hashLen);
    const emptyHash = tlsHash(suite.hashAlg, Buffer.alloc(0));
    const earlySecret = hkdfExtract(suite.hashAlg, zeroHash, zeroHash);
    const derivedEarly = deriveSecret(suite.hashAlg, earlySecret, 'derived', emptyHash);

    const ecdheShared = activeKeyShare.computeSharedSecret(sh.keySharePublicKey);
    const handshakeSecret = hkdfExtract(suite.hashAlg, derivedEarly, ecdheShared);
    ecdheShared.fill(0);
    earlySecret.fill(0);
    derivedEarly.fill(0);

    const shTranscriptHash = tlsHash(suite.hashAlg, activeTranscript);
    const clientHsTrafficSecret = deriveSecret(
      suite.hashAlg,
      handshakeSecret,
      'c hs traffic',
      shTranscriptHash,
    );
    const serverHsTrafficSecret = deriveSecret(
      suite.hashAlg,
      handshakeSecret,
      's hs traffic',
      shTranscriptHash,
    );

    clientHsCipher = new Tls13RecordCipher(suite, clientHsTrafficSecret);
    serverHsCipher = new Tls13RecordCipher(suite, serverHsTrafficSecret);
    transport.setReadCipher(serverHsCipher);
    transport.setWriteCipher(clientHsCipher);

    // Read encrypted server handshake flight:
    // 1. EncryptedExtensions (0x08)
    const eeMsg = await transport.readHandshakeMessage();
    if (eeMsg.type !== TLS_HS_ENCRYPTED_EXTENSIONS) {
      throw new TlsProtocolError(
        `expected EncryptedExtensions (0x08), got 0x${eeMsg.type.toString(16)}`,
        { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
      );
    }
    activeTranscript.push(eeMsg.raw);
    const offeredSni = echAccepted ? !isIpLiteral(stripBrackets(opts.realHost)) : true;
    const ee = parseEncryptedExtensions(eeMsg.body, offeredAlpn, offeredSni);

    if (echAccepted && ee.hasEchExt) {
      // RFC 9849 §7.2: EncryptedExtensions MUST NOT include 0xfe0d when ECH is accepted.
      throw new TlsProtocolError(
        'server sent encrypted_client_hello in EncryptedExtensions after accepting ECH',
        { alertDescription: TLS_ALERT_UNSUPPORTED_EXTENSION },
      );
    }

    // 2. Optional CertificateRequest (0x0d) then Certificate (0x0b)
    let certReqReceived = false;
    let certReqContext: Buffer = Buffer.alloc(0);
    let nextMsg = await transport.readHandshakeMessage();
    if (nextMsg.type === TLS_HS_CERTIFICATE_REQUEST) {
      if (nextMsg.body.length < 3 || 1 + nextMsg.body[0] + 2 > nextMsg.body.length) {
        throw new TlsProtocolError('malformed CertificateRequest message', {
          alertDescription: TLS_ALERT_DECODE_ERROR,
        });
      }
      const ctxLen = nextMsg.body[0];
      certReqContext = Buffer.from(nextMsg.body.subarray(1, 1 + ctxLen));
      certReqReceived = true;
      activeTranscript.push(nextMsg.raw);
      nextMsg = await transport.readHandshakeMessage();
    }

    if (nextMsg.type !== TLS_HS_CERTIFICATE) {
      throw new TlsProtocolError(
        `expected Certificate (0x0b), got 0x${nextMsg.type.toString(16)}`,
        { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
      );
    }
    activeTranscript.push(nextMsg.raw);
    const certDers = parseCertificateMessage(nextMsg.body);

    let leafCert: crypto.X509Certificate;
    if (opts.noTlsVerify) {
      try {
        leafCert = new crypto.X509Certificate(certDers[0]);
      } catch (err) {
        throw new TlsProtocolError('failed to parse server leaf certificate', {
          code: 'TLS_CERT_PARSE_ERROR',
          alertDescription: TLS_ALERT_BAD_CERTIFICATE,
          cause: err,
        });
      }
    } else {
      // Strictly verify chain & hostname against `realHost` (accepted) OR `public_name` (rejected)!
      leafCert = verifyX509Chain(certDers, targetVerifyHost, { ca: opts.ca });
    }

    // 3. CertificateVerify (0x0f) — verified against transcript BEFORE CertificateVerify
    const cvMsg = await transport.readHandshakeMessage();
    if (cvMsg.type !== TLS_HS_CERTIFICATE_VERIFY) {
      throw new TlsProtocolError(
        `expected CertificateVerify (0x0f), got 0x${cvMsg.type.toString(16)}`,
        { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
      );
    }
    const { scheme, signature } = parseCertificateVerify(cvMsg.body);
    const preCvHash = tlsHash(suite.hashAlg, activeTranscript);
    if (!verifyCertificateVerifySignature(leafCert, scheme, signature, preCvHash)) {
      throw new TlsProtocolError(
        `TLS 1.3 CertificateVerify signature verification failed (scheme 0x${scheme.toString(16)})`,
        { code: 'TLS_CERT_VERIFY_FAILED', alertDescription: TLS_ALERT_DECRYPT_ERROR },
      );
    }
    activeTranscript.push(cvMsg.raw);

    // 4. Server Finished (0x14) — verified against transcript BEFORE Finished
    const sfMsg = await transport.readHandshakeMessage();
    if (sfMsg.type !== TLS_HS_FINISHED) {
      throw new TlsProtocolError(
        `expected server Finished (0x14), got 0x${sfMsg.type.toString(16)}`,
        { alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE },
      );
    }
    if (sfMsg.body.length !== suite.hashLen) {
      throw new TlsProtocolError(
        `server Finished verify_data length mismatch (expected ${suite.hashLen}, got ${sfMsg.body.length})`,
        { alertDescription: TLS_ALERT_DECODE_ERROR },
      );
    }
    const preSfHash = tlsHash(suite.hashAlg, activeTranscript);
    const expectedServerVerify = computeFinishedVerifyData(suite, serverHsTrafficSecret, preSfHash);
    if (!crypto.timingSafeEqual(sfMsg.body, expectedServerVerify)) {
      throw new TlsProtocolError('server Finished verify_data verification failed', {
        code: 'TLS_FINISHED_FAILED',
        alertDescription: TLS_ALERT_DECRYPT_ERROR,
      });
    }
    activeTranscript.push(sfMsg.raw);

    // RFC 8446 §5.1: no leftover handshake bytes across handshake->application key switch
    if (transport.hasPendingHandshakeBytes()) {
      throw new TlsProtocolError('unexpected trailing handshake bytes after server Finished', {
        alertDescription: TLS_ALERT_UNEXPECTED_MESSAGE,
      });
    }

    // -----------------------------------------------------------------------
    // RFC 9849 §7.2 ECH Rejection Path (ONLY AFTER outer cert + CV + Finished!)
    // -----------------------------------------------------------------------
    if (!echAccepted) {
      let validatedRetryConfigs: Buffer | undefined;
      if (ee.echRetryConfigs && ee.echRetryConfigs.length > 0) {
        try {
          const parsedRetries = parseEchConfigList(ee.echRetryConfigs);
          if (parsedRetries.length > 0) {
            validatedRetryConfigs = ee.echRetryConfigs;
          }
        } catch {
          // Malformed retry_configs; still abort with ech_required without retrying.
        }
      }

      // Send encrypted fatal alert `ech_required (0x79)` and close TCP with ZERO app data sent!
      await transport.sendAlertAndClose(TLS_ALERT_ECH_REQUIRED, TLS_ALERT_FATAL);
      handshakeSecret.fill(0);
      clientHsTrafficSecret.fill(0);
      serverHsTrafficSecret.fill(0);
      clientHsCipher.destroy();
      serverHsCipher.destroy();
      sealer.destroy();

      throw new EchRejectedError(
        validatedRetryConfigs
          ? `server rejected ECH for '${opts.realHost}' (authenticated outer '${selected.config.publicName}' supplied retry_configs)`
          : `server rejected ECH for '${opts.realHost}' (authenticated outer '${selected.config.publicName}' supplied no usable retry_configs)`,
        {
          publicName: selected.config.publicName,
          retryConfigs: validatedRetryConfigs,
        },
      );
    }

    // -----------------------------------------------------------------------
    // ECH Accepted: derive application traffic keys & send client Finished
    // -----------------------------------------------------------------------
    const postSfHash = tlsHash(suite.hashAlg, activeTranscript);
    const derivedHs = deriveSecret(suite.hashAlg, handshakeSecret, 'derived', emptyHash);
    const masterSecret = hkdfExtract(suite.hashAlg, derivedHs, zeroHash);
    handshakeSecret.fill(0);
    derivedHs.fill(0);

    const clientAppSecret = deriveSecret(suite.hashAlg, masterSecret, 'c ap traffic', postSfHash);
    const serverAppSecret = deriveSecret(suite.hashAlg, masterSecret, 's ap traffic', postSfHash);
    masterSecret.fill(0);

    // If server requested a client certificate, send an empty Certificate message echoing certificate_request_context.
    const clientFlightMsgs: Buffer[] = [];
    if (certReqReceived) {
      const emptyCertBody = Buffer.concat([
        Buffer.from([certReqContext.length]),
        certReqContext,
        Buffer.from([0x00, 0x00, 0x00]),
      ]);
      const emptyCertMsg = wrapHandshakeMessage(TLS_HS_CERTIFICATE, emptyCertBody);
      activeTranscript.push(emptyCertMsg);
      clientFlightMsgs.push(emptyCertMsg);
    }

    const clientFinHash = tlsHash(suite.hashAlg, activeTranscript);
    const clientVerifyData = computeFinishedVerifyData(suite, clientHsTrafficSecret, clientFinHash);
    const clientFinMsg = wrapHandshakeMessage(TLS_HS_FINISHED, clientVerifyData);
    clientFlightMsgs.push(clientFinMsg);

    const clientFlightRec = clientHsCipher.encryptRecord(
      TLS_CONTENT_HANDSHAKE,
      Buffer.concat(clientFlightMsgs),
    );
    await transport.writeRaw(clientFlightRec);

    // Transition cleanly to application traffic ciphers & Tls13EchDuplex
    const clientAppCipher = new Tls13RecordCipher(suite, clientAppSecret);
    const serverAppCipher = new Tls13RecordCipher(suite, serverAppSecret);
    clientAppSecret.fill(0);
    serverAppSecret.fill(0);
    clientHsTrafficSecret.fill(0);
    serverHsTrafficSecret.fill(0);
    clientHsCipher.destroy();
    serverHsCipher.destroy();
    sealer.destroy();

    const leftoverBytes = transport.detachForDuplex();

    return new Tls13EchDuplex({
      raw: socket,
      clientCipher: clientAppCipher,
      serverCipher: serverAppCipher,
      leftoverBytes,
      leafCert,
      authorized: !opts.noTlsVerify,
      alpnProtocol: ee.alpn ?? false,
      outerSni: selected.config.publicName,
      realHost: opts.realHost,
      cipherSuite: suite,
      echRetried: Boolean(opts.isRetry),
    });
  } catch (err) {
    sealer.destroy();
    if (err instanceof EchRejectedError) {
      // Alert & socket teardown already performed above.
      throw err;
    }

    // Send appropriate TLS fatal alert before destroying socket.
    const alertDesc =
      err instanceof TlsProtocolError && err.alertDescription !== undefined
        ? err.alertDescription
        : undefined;
    if (alertDesc !== undefined && !(err instanceof TlsProtocolError && err.code === 'TLS_PEER_ALERT')) {
      await transport.sendAlertAndClose(alertDesc, TLS_ALERT_FATAL);
    } else {
      socket.on('error', () => {});
      transport.cleanupListeners();
      if (!socket.destroyed) {
        socket.destroy();
      }
    }
    clientHsCipher?.destroy();
    serverHsCipher?.destroy();
    throw err;
  }
}

export interface ConnectTls13EchOptions {
  readonly realHost: string;
  readonly echConfigList: Buffer | readonly Buffer[];
  readonly connectTcp: (remainingMs: number) => Promise<{ socket: net.Socket; address: string }>;
  readonly noTlsVerify?: boolean;
  readonly ca?: string | Buffer | Array<string | Buffer>;
  readonly alpn?: readonly string[];
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
  readonly onWarn?: (message: string) => void;
}

export interface ConnectTls13EchResult {
  readonly duplex: Tls13EchDuplex;
  readonly address: string;
  readonly outerSni: string;
  readonly echStatus: 'accepted';
  readonly echRetried: boolean;
}

/**
 * Connect TLS 1.3 + ECH with RFC 9849 1-shot `retry_configs` retry on a fresh TCP socket.
 */
export async function connectTls13EchWithRetry(
  opts: ConnectTls13EchOptions,
): Promise<ConnectTls13EchResult> {
  const totalBudgetMs = opts.timeoutMs ?? 10_000;
  const deadline = Date.now() + totalBudgetMs;

  let currentEchList: Buffer | readonly Buffer[] = opts.echConfigList;
  let retried = false;

  while (true) {
    if (opts.signal?.aborted) {
      throw new NerutonError('tunnel connection aborted', 'ABORTED');
    }

    // Validate compatibility before dialing TCP so invalid configs fail fast without wasting a socket.
    const preSelected: SelectedEchConfig | null = selectEchConfig(currentEchList);
    if (!preSelected) {
      throw new NerutonError(
        'no compatible ECHConfig found in ECHConfigList for supported HPKE suites',
        'ECH_INVALID_CONFIG',
      );
    }

    const remainingBeforeTcp = deadline - Date.now();
    if (remainingBeforeTcp <= 0) {
      throw new TlsProtocolError('TLS 1.3 ECH connection timed out', { code: 'TLS_TIMEOUT' });
    }

    const tcpConn = await opts.connectTcp(remainingBeforeTcp);
    if (opts.signal?.aborted) {
      tcpConn.socket.on('error', () => {});
      if (!tcpConn.socket.destroyed) tcpConn.socket.destroy();
      throw new NerutonError('tunnel connection aborted', 'ABORTED');
    }

    const remainingForHs = Math.max(500, deadline - Date.now());
    try {
      const duplex = await performTls13EchHandshake(tcpConn.socket, {
        realHost: opts.realHost,
        echConfigList: currentEchList,
        noTlsVerify: opts.noTlsVerify,
        ca: opts.ca,
        alpn: opts.alpn,
        timeoutMs: remainingForHs,
        signal: opts.signal,
        isRetry: retried,
      });

      return {
        duplex,
        address: tcpConn.address,
        outerSni: duplex.outerSni,
        echStatus: 'accepted',
        echRetried: retried,
      };
    } catch (err) {
      if (err instanceof EchRejectedError && !retried && err.retryConfigs && err.retryConfigs.length > 0) {
        const retrySelected = selectEchConfig(err.retryConfigs);
        if (retrySelected) {
          opts.onWarn?.(
            `Server rejected initial ECH config (outer: ${err.publicName}) and supplied retry_configs; retrying ECH once.`,
          );
          currentEchList = err.retryConfigs;
          retried = true;
          continue;
        }
      }
      throw err;
    }
  }
}

export type { ParsedEchConfig, SelectedEchConfig };
