import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { Duplex } from 'node:stream';
import { WebSocketServer } from 'ws';
import {
  HPKE_AEAD_AES_128_GCM,
  HPKE_KDF_HKDF_SHA256,
  HPKE_KEM_X25519_SHA256,
  TLS_AES_128_GCM_SHA256,
  TLS_AES_256_GCM_SHA384,
  TLS_ALERT_ECH_REQUIRED,
  TLS_CHACHA20_POLY1305_SHA256,
  TLS_CONTENT_ALERT,
  TLS_CONTENT_APPLICATION_DATA,
  TLS_CONTENT_CHANGE_CIPHER_SPEC,
  TLS_CONTENT_HANDSHAKE,
  TLS_EXT_ALPN,
  TLS_EXT_COOKIE,
  TLS_EXT_ECH,
  TLS_EXT_KEY_SHARE,
  TLS_EXT_SERVER_NAME,
  TLS_EXT_SUPPORTED_VERSIONS,
  TLS_GROUP_SECP256R1,
  TLS_GROUP_X25519,
  TLS_HRR_RANDOM,
  TLS_HS_CERTIFICATE,
  TLS_HS_CERTIFICATE_VERIFY,
  TLS_HS_CLIENT_HELLO,
  TLS_HS_ENCRYPTED_EXTENSIONS,
  TLS_HS_FINISHED,
  TLS_HS_KEY_UPDATE,
  TLS_HS_MESSAGE_HASH,
  TLS_HS_NEW_SESSION_TICKET,
  TLS_HS_SERVER_HELLO,
  TLS_MAX_PLAINTEXT,
  TLS_SIG_ECDSA_SECP256R1_SHA256,
  TLS_SIG_ECDSA_SECP384R1_SHA384,
  TLS_SIG_ED25519,
  TLS_SIG_RSA_PSS_RSAE_SHA256,
  Tls13RecordCipher,
  TlsProtocolError,
  EchRejectedError,
  WsByteStream,
  YamuxSession,
  buildEchClientHelloPair,
  computeEchAcceptConfirmation,
  computeFinishedVerifyData,
  computeHrrEchAcceptConfirmation,
  connect,
  connectTcpWithFailover,
  connectTls13EchWithRetry,
  deriveSecret,
  encodeEchConfig,
  encodeEchConfigList,
  generateHpkeKeyPair,
  getCipherSuiteSpec,
  hkdfExtract,
  padEncodedClientHelloInner,
  performTls13EchHandshake,
  planStealthTls,
  selectEchConfig,
  setupBaseR,
  setupBaseS,
  tlsHash,
  verifyX509Chain,
} from '../dist/esm/index.js';

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff, 0);
  return b;
}

function u24(n) {
  return Buffer.from([(n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

function wrapHs(type, body) {
  return Buffer.concat([Buffer.from([type]), u24(body.length), body]);
}

function wrapRec(type, payload, verMinor = 0x03) {
  return Buffer.concat([Buffer.from([type, 0x03, verMinor]), u16(payload.length), payload]);
}

function ext(type, data) {
  return Buffer.concat([u16(type), u16(data.length), data]);
}

function runOpenssl(args, cwd) {
  execFileSync('openssl', args, { cwd, stdio: 'ignore' });
}

function pemToDer(pemBuf) {
  const txt = Buffer.isBuffer(pemBuf) ? pemBuf.toString('utf8') : pemBuf;
  const b64 = txt.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return Buffer.from(b64, 'base64');
}

/**
 * Generate a full OpenSSL PKI chain (Root CA -> Intermediate CA -> Leaf) plus edge-case certs for strict X.509 testing.
 */
function buildSyntheticPki() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-x509-'));

  // 1. Root CA (RSA 2048, CA:TRUE)
  fs.writeFileSync(
    path.join(dir, 'root.ext'),
    'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n',
  );
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'root.key'], dir);
  runOpenssl(
    [
      'req',
      '-new',
      '-x509',
      '-key',
      'root.key',
      '-out',
      'root.pem',
      '-days',
      '30',
      '-subj',
      '/CN=Test Root CA',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
    ],
    dir,
  );

  // 2. Intermediate CA (RSA 2048, CA:TRUE, serverAuth EKU)
  fs.writeFileSync(
    path.join(dir, 'inter.ext'),
    'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n',
  );
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'inter.key'], dir);
  runOpenssl(['req', '-new', '-key', 'inter.key', '-out', 'inter.csr', '-subj', '/CN=Test Inter CA'], dir);
  runOpenssl(
    ['x509', '-req', '-in', 'inter.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'inter.pem', '-days', '15', '-extfile', 'inter.ext'],
    dir,
  );

  const issueLeaf = (name, keyArgs, cn, extContent, caCert = 'inter.pem', caKey = 'inter.key', dateArgs = ['-days', '5']) => {
    fs.writeFileSync(path.join(dir, `${name}.ext`), extContent);
    runOpenssl(['genpkey', ...keyArgs, '-out', `${name}.key`], dir);
    runOpenssl(['req', '-new', '-key', `${name}.key`, '-out', `${name}.csr`, '-subj', `/CN=${cn}`], dir);
    runOpenssl(
      ['x509', '-req', '-in', `${name}.csr`, '-CA', caCert, '-CAkey', caKey, '-CAcreateserial', '-out', `${name}.pem`, ...dateArgs, '-extfile', `${name}.ext`],
      dir,
    );
    return {
      keyPem: fs.readFileSync(path.join(dir, `${name}.key`)),
      certPem: fs.readFileSync(path.join(dir, `${name}.pem`)),
      certDer: pemToDer(fs.readFileSync(path.join(dir, `${name}.pem`))),
    };
  };

  // Valid RSA leaf for secret.neruton.test
  const leafRsa = issueLeaf(
    'leaf-rsa',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:secret.neruton.test,DNS:*.wild.neruton.test,IP:127.0.0.1\n',
  );

  // Valid ECDSA P-256 leaf
  const leafP256 = issueLeaf(
    'leaf-p256',
    ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:secret.neruton.test\n',
  );

  // Valid ECDSA P-384 leaf
  const leafP384 = issueLeaf(
    'leaf-p384',
    ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:secp384r1'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:secret.neruton.test\n',
  );

  // Valid Ed25519 leaf
  const leafEd25519 = issueLeaf(
    'leaf-ed25519',
    ['-algorithm', 'ED25519'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:secret.neruton.test\n',
  );

  // Valid outer public_name leaf (outer-ech.test)
  const leafOuter = issueLeaf(
    'leaf-outer',
    ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:prime256v1'],
    'outer-ech.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:outer-ech.test\n',
  );

  // Wrong EKU leaf (clientAuth only — must be rejected for serverAuth!)
  const leafClientEku = issueLeaf(
    'leaf-client-eku',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:secret.neruton.test\n',
  );

  // Non-CA leaf attempting to sign a child cert (must be rejected because issuer.ca === false!)
  const childOfNonCa = issueLeaf(
    'child-non-ca',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'forged.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:forged.neruton.test\n',
    'leaf-rsa.pem',
    'leaf-rsa.key',
  );

  // Separate untrusted root
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'untrusted.key'], dir);
  runOpenssl(
    [
      'req',
      '-new',
      '-x509',
      '-key',
      'untrusted.key',
      '-out',
      'untrusted.pem',
      '-days',
      '30',
      '-subj',
      '/CN=Untrusted Root',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
    ],
    dir,
  );
  const leafUntrusted = issueLeaf(
    'leaf-untrusted',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:secret.neruton.test\n',
    'untrusted.pem',
    'untrusted.key',
  );

  // Cyclic CA pair (A issued by B, B issued by A — neither trusted)
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'cycA.key'], dir);
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'cycB.key'], dir);
  runOpenssl(
    [
      'req',
      '-new',
      '-x509',
      '-key',
      'cycA.key',
      '-out',
      'cycA0.pem',
      '-days',
      '5',
      '-subj',
      '/CN=Cycle A',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
    ],
    dir,
  );
  runOpenssl(['req', '-new', '-key', 'cycB.key', '-out', 'cycB.csr', '-subj', '/CN=Cycle B'], dir);
  runOpenssl(['x509', '-req', '-in', 'cycB.csr', '-CA', 'cycA0.pem', '-CAkey', 'cycA.key', '-CAcreateserial', '-out', 'cycB.pem', '-days', '5', '-extfile', 'root.ext'], dir);
  runOpenssl(['req', '-new', '-key', 'cycA.key', '-out', 'cycA.csr', '-subj', '/CN=Cycle A'], dir);
  runOpenssl(['x509', '-req', '-in', 'cycA.csr', '-CA', 'cycB.pem', '-CAkey', 'cycB.key', '-CAcreateserial', '-out', 'cycA.pem', '-days', '5', '-extfile', 'root.ext'], dir);
  const leafCyc = issueLeaf(
    'leaf-cyc',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:secret.neruton.test\n',
    'cycA.pem',
    'cycA.key',
  );

  // Also test CN-only cert (no SAN extension) -> must be rejected by strict verifyX509Chain!
  const leafCnOnly = issueLeaf(
    'leaf-cn-only',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'secret.neruton.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n',
  );

  // PathLenConstraint test chains (RFC 5280 §6.1.4):
  // 1) Root -> inter (pathlen:0) -> subCaUnderPathlen0 (CA:TRUE) -> leafUnderPathlen0 (MUST FAIL!)
  fs.writeFileSync(
    path.join(dir, 'subca.ext'),
    'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=serverAuth\n',
  );
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'subca0.key'], dir);
  runOpenssl(['req', '-new', '-key', 'subca0.key', '-out', 'subca0.csr', '-subj', '/CN=Sub CA Under PathLen0'], dir);
  runOpenssl(
    ['x509', '-req', '-in', 'subca0.csr', '-CA', 'inter.pem', '-CAkey', 'inter.key', '-CAcreateserial', '-out', 'subca0.pem', '-days', '10', '-extfile', 'subca.ext'],
    dir,
  );
  const leafUnderPathlen0 = issueLeaf(
    'leaf-pathlen0',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'pathlen.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pathlen.test\n',
    'subca0.pem',
    'subca0.key',
  );

  // 2) Root -> interPathlen1 (pathlen:1) -> subCaUnderPathlen1 (CA:TRUE) -> leafUnderPathlen1 (MUST PASS!)
  fs.writeFileSync(
    path.join(dir, 'inter1.ext'),
    'basicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\nextendedKeyUsage=serverAuth\n',
  );
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'inter1.key'], dir);
  runOpenssl(['req', '-new', '-key', 'inter1.key', '-out', 'inter1.csr', '-subj', '/CN=Inter CA PathLen1'], dir);
  runOpenssl(
    ['x509', '-req', '-in', 'inter1.csr', '-CA', 'root.pem', '-CAkey', 'root.key', '-CAcreateserial', '-out', 'inter1.pem', '-days', '15', '-extfile', 'inter1.ext'],
    dir,
  );
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'subca1.key'], dir);
  runOpenssl(['req', '-new', '-key', 'subca1.key', '-out', 'subca1.csr', '-subj', '/CN=Sub CA Under PathLen1'], dir);
  runOpenssl(
    ['x509', '-req', '-in', 'subca1.csr', '-CA', 'inter1.pem', '-CAkey', 'inter1.key', '-CAcreateserial', '-out', 'subca1.pem', '-days', '10', '-extfile', 'subca.ext'],
    dir,
  );
  const leafUnderPathlen1 = issueLeaf(
    'leaf-pathlen1',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'pathlen.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pathlen.test\n',
    'subca1.pem',
    'subca1.key',
  );

  // 3) Root with pathlen:0 -> inter (CA:TRUE) -> leaf (MUST FAIL on anchor pathlen:0!)
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'root0.key'], dir);
  runOpenssl(
    [
      'req',
      '-new',
      '-x509',
      '-key',
      'root0.key',
      '-out',
      'root0.pem',
      '-days',
      '30',
      '-subj',
      '/CN=Root PathLen0',
      '-addext',
      'basicConstraints=critical,CA:TRUE,pathlen:0',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
    ],
    dir,
  );
  runOpenssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', 'inter_r0.key'], dir);
  runOpenssl(['req', '-new', '-key', 'inter_r0.key', '-out', 'inter_r0.csr', '-subj', '/CN=Inter Under Root PathLen0'], dir);
  runOpenssl(
    ['x509', '-req', '-in', 'inter_r0.csr', '-CA', 'root0.pem', '-CAkey', 'root0.key', '-CAcreateserial', '-out', 'inter_r0.pem', '-days', '10', '-extfile', 'subca.ext'],
    dir,
  );
  const leafUnderRootPathlen0 = issueLeaf(
    'leaf-root-pathlen0',
    ['-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    'pathlen.test',
    'basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:pathlen.test\n',
    'inter_r0.pem',
    'inter_r0.key',
  );

  return {
    dir,
    rootPem: fs.readFileSync(path.join(dir, 'root.pem')),
    rootDer: pemToDer(fs.readFileSync(path.join(dir, 'root.pem'))),
    interPem: fs.readFileSync(path.join(dir, 'inter.pem')),
    interDer: pemToDer(fs.readFileSync(path.join(dir, 'inter.pem'))),
    leafRsa,
    leafP256,
    leafP384,
    leafEd25519,
    leafOuter,
    leafClientEku,
    childOfNonCa,
    leafUntrusted,
    leafCnOnly,
    subCa0Der: pemToDer(fs.readFileSync(path.join(dir, 'subca0.pem'))),
    leafUnderPathlen0,
    inter1Der: pemToDer(fs.readFileSync(path.join(dir, 'inter1.pem'))),
    subCa1Der: pemToDer(fs.readFileSync(path.join(dir, 'subca1.pem'))),
    leafUnderPathlen1,
    root0Pem: fs.readFileSync(path.join(dir, 'root0.pem')),
    interR0Der: pemToDer(fs.readFileSync(path.join(dir, 'inter_r0.pem'))),
    leafUnderRootPathlen0,
    cycADer: pemToDer(fs.readFileSync(path.join(dir, 'cycA.pem'))),
    cycBDer: pemToDer(fs.readFileSync(path.join(dir, 'cycB.pem'))),
    leafCyc,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

// ---------------------------------------------------------------------------
// Real Cryptographic Mock RFC 9849 TLS 1.3 + ECH Server for Deterministic Testing
// ---------------------------------------------------------------------------

function parseClientHelloBody(body) {
  let pos = 2; // legacy_version
  const random = Buffer.from(body.subarray(pos, pos + 32));
  pos += 32;
  const sidLen = body[pos];
  pos += 1;
  const sessionId = Buffer.from(body.subarray(pos, pos + sidLen));
  pos += sidLen;
  const csLen = body.readUInt16BE(pos);
  pos += 2 + csLen;
  const compLen = body[pos];
  pos += 1 + compLen;
  const extsLen = body.readUInt16BE(pos);
  pos += 2;
  const extsEnd = pos + extsLen;

  let sni = null;
  let echExt = null;
  let echPayloadOffset = -1;
  let echPayloadLen = 0;
  let cookie = null;
  const keyShares = new Map();

  while (pos < extsEnd) {
    const type = body.readUInt16BE(pos);
    const len = body.readUInt16BE(pos + 2);
    pos += 4;
    const data = body.subarray(pos, pos + len);
    if (type === TLS_EXT_SERVER_NAME && len >= 5) {
      const nameLen = data.readUInt16BE(3);
      sni = data.subarray(5, 5 + nameLen).toString('ascii');
    } else if (type === TLS_EXT_KEY_SHARE) {
      let kp = 2;
      while (kp + 4 <= data.length) {
        const g = data.readUInt16BE(kp);
        const kl = data.readUInt16BE(kp + 2);
        keyShares.set(g, Buffer.from(data.subarray(kp + 4, kp + 4 + kl)));
        kp += 4 + kl;
      }
    } else if (type === TLS_EXT_COOKIE) {
      cookie = Buffer.from(data.subarray(2));
    } else if (type === TLS_EXT_ECH) {
      const echType = data[0];
      if (echType === 0) {
        const kdfId = data.readUInt16BE(1);
        const aeadId = data.readUInt16BE(3);
        const configId = data[5];
        const encLen = data.readUInt16BE(6);
        const enc = Buffer.from(data.subarray(8, 8 + encLen));
        const pLenPos = 8 + encLen;
        const payloadLen = data.readUInt16BE(pLenPos);
        const payloadStart = pos + pLenPos + 2;
        const payload = Buffer.from(body.subarray(payloadStart, payloadStart + payloadLen));
        echPayloadOffset = payloadStart;
        echPayloadLen = payloadLen;
        echExt = { type: 0, kdfId, aeadId, configId, enc, payload };
      } else {
        echExt = { type: echType };
      }
    }
    pos += len;
  }

  return { random, sessionId, sni, keyShares, cookie, echExt, echPayloadOffset, echPayloadLen };
}

function reconstructClientHelloInner(encodedBody, outerSessionId) {
  // Replace empty legacy_session_id (offset 34: 0x00) with outerSessionId, strip trailing padding
  let pos = 2 + 32;
  assert.equal(encodedBody[pos], 0, 'EncodedClientHelloInner must have empty legacy_session_id');
  pos += 1;
  const csLen = encodedBody.readUInt16BE(pos);
  pos += 2 + csLen;
  const compLen = encodedBody[pos];
  pos += 1 + compLen;
  const extsLen = encodedBody.readUInt16BE(pos);
  const innerEnd = pos + 2 + extsLen;

  const logicalBody = Buffer.concat([
    encodedBody.subarray(0, 34),
    Buffer.from([outerSessionId.length]),
    outerSessionId,
    encodedBody.subarray(35, innerEnd),
  ]);
  return {
    parsed: parseClientHelloBody(logicalBody),
    rawMsg: wrapHs(TLS_HS_CLIENT_HELLO, logicalBody),
  };
}

function signCertificateVerify(keyPem, scheme, transcriptHash) {
  const content = Buffer.concat([
    Buffer.alloc(64, 0x20),
    Buffer.from('TLS 1.3, server CertificateVerify\x00', 'ascii'),
    transcriptHash,
  ]);
  const priv = crypto.createPrivateKey(keyPem);
  switch (scheme) {
    case TLS_SIG_ECDSA_SECP256R1_SHA256:
      return crypto.sign('sha256', content, priv);
    case TLS_SIG_ECDSA_SECP384R1_SHA384:
      return crypto.sign('sha384', content, priv);
    case TLS_SIG_ED25519:
      return crypto.sign(null, content, priv);
    case TLS_SIG_RSA_PSS_RSAE_SHA256:
      return crypto.sign('sha256', content, {
        key: priv,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      });
    default:
      throw new Error(`unsupported test scheme 0x${scheme.toString(16)}`);
  }
}

function startMockTls13EchServer(config) {
  const state = {
    connections: [],
  };
  const openSockets = new Set();

  const server = net.createServer((sock) => {
    openSockets.add(sock);
    sock.once('close', () => openSockets.delete(sock));
    const connLog = {
      outerSni: null,
      innerSni: null,
      echAccepted: false,
      hrrSent: false,
      alertsReceived: [],
      appBytesReceived: Buffer.alloc(0),
      keyUpdateReceived: false,
    };
    state.connections.push(connLog);
    sock.on('error', () => {});

    let rawBuf = Buffer.alloc(0);
    let wake = null;
    let closed = false;
    sock.on('data', (c) => {
      rawBuf = Buffer.concat([rawBuf, c]);
      const fn = wake;
      wake = null;
      fn?.();
    });
    sock.on('close', () => {
      closed = true;
      const fn = wake;
      wake = null;
      fn?.();
    });

    const waitData = () =>
      new Promise((resolve, reject) => {
        if (closed) return reject(new Error('socket closed'));
        wake = resolve;
      });

    const readRec = async () => {
      while (rawBuf.length < 5) await waitData();
      const type = rawBuf[0];
      const len = rawBuf.readUInt16BE(3);
      while (rawBuf.length < 5 + len) await waitData();
      const header = Buffer.from(rawBuf.subarray(0, 5));
      const payload = Buffer.from(rawBuf.subarray(5, 5 + len));
      rawBuf = rawBuf.subarray(5 + len);
      return { type, header, payload };
    };

    const run = async () => {
      const suiteId = config.cipherSuite ?? TLS_AES_128_GCM_SHA256;
      const suite = getCipherSuiteSpec(suiteId);
      const hpkeSuite = {
        kemId: HPKE_KEM_X25519_SHA256,
        kdfId: HPKE_KDF_HKDF_SHA256,
        aeadId: HPKE_AEAD_AES_128_GCM,
      };
      const hpkeInfo = Buffer.concat([Buffer.from('tls ech\0', 'ascii'), config.rawEchConfig]);

      // Read CH1
      const ch1Rec = await readRec();
      assert.equal(ch1Rec.type, TLS_CONTENT_HANDSHAKE);
      const ch1OuterMsg = ch1Rec.payload;
      const ch1OuterBody = ch1OuterMsg.subarray(4);
      const ch1Outer = parseClientHelloBody(ch1OuterBody);
      connLog.outerSni = ch1Outer.sni;

      const tryDecryptEch = (outerBody, outerParsed, existingOpener) => {
        if (!outerParsed.echExt || !config.acceptEch) return { ok: false, opener: null };
        if (outerParsed.echExt.configId !== config.configId) return { ok: false, opener: null };
        const aad = Buffer.from(outerBody);
        aad.fill(0, outerParsed.echPayloadOffset, outerParsed.echPayloadOffset + outerParsed.echPayloadLen);
        try {
          const opener =
            existingOpener ??
            setupBaseR(hpkeSuite, outerParsed.echExt.enc, config.echPrivateKey, hpkeInfo);
          const encodedInner = opener.open(aad, outerParsed.echExt.payload);
          const inner = reconstructClientHelloInner(encodedInner, outerParsed.sessionId);
          return { ok: true, opener, inner };
        } catch {
          return { ok: false, opener: null };
        }
      };

      let dec1 = tryDecryptEch(ch1OuterBody, ch1Outer, null);
      let echAccepted = dec1.ok;
      let opener = dec1.opener;
      let chActiveParsed = echAccepted ? dec1.inner.parsed : ch1Outer;
      let transcript = [echAccepted ? dec1.inner.rawMsg : ch1OuterMsg];
      let innerRandom = echAccepted ? dec1.inner.parsed.random : null;
      if (echAccepted) connLog.innerSni = dec1.inner.parsed.sni;

      // Optional HRR flow
      if (config.requireHrrGroup || config.requireCookie) {
        connLog.hrrSent = true;
        const hrrExts = [ext(TLS_EXT_SUPPORTED_VERSIONS, u16(0x0304))];
        if (config.requireHrrGroup) {
          hrrExts.push(ext(TLS_EXT_KEY_SHARE, u16(config.requireHrrGroup)));
        }
        if (config.requireCookie) {
          hrrExts.push(ext(TLS_EXT_COOKIE, Buffer.concat([u16(config.requireCookie.length), config.requireCookie])));
        }
        if (echAccepted) {
          hrrExts.push(ext(TLS_EXT_ECH, Buffer.alloc(8, 0x00)));
        }
        const hrrExtsBuf = Buffer.concat(hrrExts);
        const hrrBody = Buffer.concat([
          Buffer.from([0x03, 0x03]),
          TLS_HRR_RANDOM,
          Buffer.from([ch1Outer.sessionId.length]),
          ch1Outer.sessionId,
          u16(suiteId),
          Buffer.from([0x00]),
          u16(hrrExtsBuf.length),
          hrrExtsBuf,
        ]);
        const hrrMsg = wrapHs(TLS_HS_SERVER_HELLO, hrrBody);
        if (echAccepted) {
          const echValOff = hrrMsg.length - 8;
          const confirm = computeHrrEchAcceptConfirmation(
            suite.hashAlg,
            innerRandom,
            dec1.inner.rawMsg,
            hrrMsg,
            echValOff,
          );
          confirm.copy(hrrMsg, echValOff);
        }

        const msgHash = Buffer.concat([
          Buffer.from([TLS_HS_MESSAGE_HASH, 0x00, 0x00, suite.hashLen]),
          tlsHash(suite.hashAlg, transcript[0]),
        ]);
        transcript = [msgHash, hrrMsg];
        sock.write(wrapRec(TLS_CONTENT_HANDSHAKE, hrrMsg));

        // Read CH2
        const ch2Rec = await readRec();
        const ch2OuterMsg = ch2Rec.payload;
        const ch2OuterBody = ch2OuterMsg.subarray(4);
        const ch2Outer = parseClientHelloBody(ch2OuterBody);
        if (config.requireCookie) {
          assert.deepEqual(ch2Outer.cookie, config.requireCookie, 'CH2 must echo HRR cookie');
        }
        if (echAccepted) {
          assert.equal(ch2Outer.echExt.enc.length, 0, 'CH2 after HRR must have empty enc');
          const dec2 = tryDecryptEch(ch2OuterBody, ch2Outer, opener);
          assert.equal(dec2.ok, true, 'CH2 HPKE seq=1 decryption must succeed');
          chActiveParsed = dec2.inner.parsed;
          transcript.push(dec2.inner.rawMsg);
        } else {
          chActiveParsed = ch2Outer;
          transcript.push(ch2OuterMsg);
        }
      }

      connLog.echAccepted = echAccepted;

      // Key exchange
      const chosenGroup = config.requireHrrGroup ?? TLS_GROUP_X25519;
      const clientPub = chActiveParsed.keyShares.get(chosenGroup);
      assert.ok(clientPub, `client missing key share for group 0x${chosenGroup.toString(16)}`);

      let serverPub;
      let sharedSecret;
      if (chosenGroup === TLS_GROUP_X25519) {
        const pair = crypto.generateKeyPairSync('x25519');
        serverPub = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
        const peerObj = crypto.createPublicKey({
          key: Buffer.concat([X25519_SPKI_PREFIX, clientPub]),
          format: 'der',
          type: 'spki',
        });
        sharedSecret = crypto.diffieHellman({ privateKey: pair.privateKey, publicKey: peerObj });
      } else {
        const ecdh = crypto.createECDH('prime256v1');
        ecdh.generateKeys();
        serverPub = ecdh.getPublicKey(null, 'uncompressed');
        sharedSecret = ecdh.computeSecret(clientPub);
      }

      // Build ServerHello
      const shRandom = crypto.randomBytes(32);
      const ksData = Buffer.concat([u16(chosenGroup), u16(serverPub.length), serverPub]);
      const shExts = Buffer.concat([
        ext(TLS_EXT_SUPPORTED_VERSIONS, u16(0x0304)),
        ext(TLS_EXT_KEY_SHARE, ksData),
      ]);
      const shBody = Buffer.concat([
        Buffer.from([0x03, 0x03]),
        shRandom,
        Buffer.from([ch1Outer.sessionId.length]),
        ch1Outer.sessionId,
        u16(suiteId),
        Buffer.from([0x00]),
        u16(shExts.length),
        shExts,
      ]);
      const shMsg = wrapHs(TLS_HS_SERVER_HELLO, shBody);

      if (echAccepted) {
        const confirm = computeEchAcceptConfirmation(suite.hashAlg, innerRandom, transcript, shMsg);
        confirm.copy(shMsg, 30);
      }
      transcript.push(shMsg);

      // Derive handshake keys
      const zeroHash = Buffer.alloc(suite.hashLen);
      const emptyHash = tlsHash(suite.hashAlg, Buffer.alloc(0));
      const earlySecret = hkdfExtract(suite.hashAlg, zeroHash, zeroHash);
      const derivedEarly = deriveSecret(suite.hashAlg, earlySecret, 'derived', emptyHash);
      const hsSecret = hkdfExtract(suite.hashAlg, derivedEarly, sharedSecret);
      const shHash = tlsHash(suite.hashAlg, transcript);
      const cHsSecret = deriveSecret(suite.hashAlg, hsSecret, 'c hs traffic', shHash);
      const sHsSecret = deriveSecret(suite.hashAlg, hsSecret, 's hs traffic', shHash);
      const sHsCipher = new Tls13RecordCipher(suite, sHsSecret);
      const cHsCipher = new Tls13RecordCipher(suite, cHsSecret);

      // Send ServerHello + optional middlebox CCS
      sock.write(wrapRec(TLS_CONTENT_HANDSHAKE, shMsg));
      if (config.sendCcs !== false) {
        sock.write(wrapRec(TLS_CONTENT_CHANGE_CIPHER_SPEC, Buffer.from([0x01])));
      }

      // EncryptedExtensions
      const eeExts = [];
      const alpnProto = Buffer.from('http/1.1', 'ascii');
      const alpnEntry = Buffer.concat([Buffer.from([alpnProto.length]), alpnProto]);
      eeExts.push(ext(TLS_EXT_ALPN, Buffer.concat([u16(alpnEntry.length), alpnEntry])));
      if (!echAccepted && config.retryConfigs) {
        eeExts.push(ext(TLS_EXT_ECH, config.retryConfigs));
      }
      const eeExtsBuf = Buffer.concat(eeExts);
      const eeMsg = wrapHs(TLS_HS_ENCRYPTED_EXTENSIONS, Buffer.concat([u16(eeExtsBuf.length), eeExtsBuf]));
      transcript.push(eeMsg);

      // Certificate
      const activeCertSpec = echAccepted ? config.innerCert : config.outerCert;
      const certEntries = activeCertSpec.chainDers.map((der) =>
        Buffer.concat([u24(der.length), der, u16(0)]),
      );
      const certList = Buffer.concat(certEntries);
      const certMsg = wrapHs(TLS_HS_CERTIFICATE, Buffer.concat([Buffer.from([0x00]), u24(certList.length), certList]));
      transcript.push(certMsg);

      // CertificateVerify
      const preCvHash = tlsHash(suite.hashAlg, transcript);
      let sig = signCertificateVerify(activeCertSpec.keyPem, activeCertSpec.sigScheme, preCvHash);
      if (config.tamperCertVerify) {
        sig = Buffer.from(sig);
        sig[sig.length - 1] ^= 0xff;
      }
      const cvMsg = wrapHs(
        TLS_HS_CERTIFICATE_VERIFY,
        Buffer.concat([u16(activeCertSpec.sigScheme), u16(sig.length), sig]),
      );
      transcript.push(cvMsg);

      // Server Finished
      const preSfHash = tlsHash(suite.hashAlg, transcript);
      const sfVerify = computeFinishedVerifyData(suite, sHsSecret, preSfHash);
      if (config.tamperServerFinished) {
        sfVerify[0] ^= 0xff;
      }
      const sfMsg = wrapHs(TLS_HS_FINISHED, sfVerify);
      transcript.push(sfMsg);

      const postSfHash = tlsHash(suite.hashAlg, transcript);
      const derivedHs = deriveSecret(suite.hashAlg, hsSecret, 'derived', emptyHash);
      const masterSecret = hkdfExtract(suite.hashAlg, derivedHs, zeroHash);
      const cAppSecret = deriveSecret(suite.hashAlg, masterSecret, 'c ap traffic', postSfHash);
      const sAppSecret = deriveSecret(suite.hashAlg, masterSecret, 's ap traffic', postSfHash);
      const sAppCipher = new Tls13RecordCipher(suite, sAppSecret);
      const cAppCipher = new Tls13RecordCipher(suite, cAppSecret);

      if (config.fragmentServerFlight) {
        // Send EncryptedExtensions + Certificate fragmented across tiny records, then CV + Finished coalesced
        const combined = Buffer.concat([eeMsg, certMsg, cvMsg, sfMsg]);
        for (let off = 0; off < combined.length; off += 120) {
          sock.write(sHsCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, combined.subarray(off, off + 120), 7));
        }
      } else {
        // Coalesced flight in one record with trailing inner plaintext zero padding
        sock.write(
          sHsCipher.encryptRecord(
            TLS_CONTENT_HANDSHAKE,
            Buffer.concat([eeMsg, certMsg, cvMsg, sfMsg]),
            16,
          ),
        );
      }

      // Immediately send NewSessionTicket coalesced right after Finished (like Cloudflare!)
      if (echAccepted && config.sendNewSessionTicket) {
        const nstBody = Buffer.concat([
          Buffer.alloc(4), // lifetime
          Buffer.alloc(4), // age_add
          Buffer.from([0x01, 0xaa]), // nonce
          u16(4),
          Buffer.from([1, 2, 3, 4]), // ticket
          u16(0), // extensions
        ]);
        sock.write(sAppCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, wrapHs(TLS_HS_NEW_SESSION_TICKET, nstBody)));
      }

      // Read client flight (Client Finished or ech_required fatal alert!)
      const cRec = await readRec();
      if (cRec.type === TLS_CONTENT_APPLICATION_DATA) {
        const dec = cHsCipher.decryptRecord(cRec.header, cRec.payload);
        if (dec.contentType === TLS_CONTENT_ALERT) {
          connLog.alertsReceived.push({ level: dec.content[0], desc: dec.content[1] });
          sock.destroy();
          return;
        }
        assert.equal(dec.contentType, TLS_CONTENT_HANDSHAKE);
        assert.equal(dec.content[0], TLS_HS_FINISHED);
        const expectedCFin = computeFinishedVerifyData(suite, cHsSecret, postSfHash);
        assert.deepEqual(dec.content.subarray(4), expectedCFin, 'client Finished verify_data must match');
      } else if (cRec.type === TLS_CONTENT_ALERT) {
        connLog.alertsReceived.push({ level: cRec.payload[0], desc: cRec.payload[1] });
        sock.destroy();
        return;
      }

      // Optional server-initiated KeyUpdate test
      if (config.keyUpdateRequest !== undefined) {
        const kuMsg = wrapHs(TLS_HS_KEY_UPDATE, Buffer.from([config.keyUpdateRequest]));
        sock.write(sAppCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, kuMsg));
        sAppCipher.rotateKeys();
      }

      // Application data echo loop (or custom handler)
      while (!closed) {
        let rec;
        try {
          rec = await readRec();
        } catch {
          break;
        }
        if (rec.type === TLS_CONTENT_CHANGE_CIPHER_SPEC) continue;
        if (rec.type !== TLS_CONTENT_APPLICATION_DATA) break;
        const dec = cAppCipher.decryptRecord(rec.header, rec.payload);
        if (dec.contentType === TLS_CONTENT_ALERT) {
          connLog.alertsReceived.push({ level: dec.content[0], desc: dec.content[1] });
          if (dec.content[1] === 0) {
            sock.end(sAppCipher.encryptRecord(TLS_CONTENT_ALERT, Buffer.from([1, 0])));
          }
          break;
        }
        if (dec.contentType === TLS_CONTENT_HANDSHAKE && dec.content[0] === TLS_HS_KEY_UPDATE) {
          connLog.keyUpdateReceived = true;
          cAppCipher.rotateKeys();
          continue;
        }
        if (dec.contentType === TLS_CONTENT_APPLICATION_DATA) {
          connLog.appBytesReceived = Buffer.concat([connLog.appBytesReceived, dec.content]);
          if (config.onAppData) {
            config.onAppData(dec.content, (reply) => {
              const maxChunk = TLS_MAX_PLAINTEXT - 5;
              for (let off = 0; off < reply.length; off += maxChunk) {
                sock.write(
                  sAppCipher.encryptRecord(
                    TLS_CONTENT_APPLICATION_DATA,
                    reply.subarray(off, off + maxChunk),
                    5,
                  ),
                );
              }
            });
          } else {
            // Echo back with inner zero padding (respecting RFC 8446 §5.4: content + padding <= 16384)
            const maxChunk = TLS_MAX_PLAINTEXT - 9;
            for (let off = 0; off < dec.content.length; off += maxChunk) {
              sock.write(
                sAppCipher.encryptRecord(
                  TLS_CONTENT_APPLICATION_DATA,
                  dec.content.subarray(off, off + maxChunk),
                  9,
                ),
              );
            }
          }
        }
      }
    };

    run().catch((err) => {
      if (!/socket closed/.test(err?.message || '')) {
        console.error('[mock-ech-server error]', err);
      }
      if (!sock.destroyed) sock.destroy();
    });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        state,
        close: () =>
          new Promise((done) => {
            for (const s of openSockets) {
              if (!s.destroyed) s.destroy();
            }
            server.close(() => done());
          }),
      });
    });
  });
}

// ===========================================================================
// 1. RFC 9849 ECH Padding, AAD, and Record Cipher Unit Tests
// ===========================================================================

test('RFC 9849 §6.1.3 padding, ClientHelloOuterAAD secrecy, and TLS 1.3 record layer checks', () => {
  // Padding with SNI shorter than maxNameLength -> always 0 mod 32
  const base = Buffer.alloc(100, 0xaa);
  const p1 = padEncodedClientHelloInner(base, 64, 'a.example.com');
  assert.equal(p1.length % 32, 0);
  assert.ok(p1.length >= 100 + (64 - 'a.example.com'.length));

  // Padding with maxNameLength = 0 -> defaults to 255
  const p2 = padEncodedClientHelloInner(base, 0, 'a.example.com');
  assert.equal(p2.length % 32, 0);
  assert.ok(p2.length >= 100 + (255 - 'a.example.com'.length));

  // Padding with no SNI (IP literal) -> L + 9
  const p3 = padEncodedClientHelloInner(base, 64, null);
  assert.equal(p3.length % 32, 0);
  assert.ok(p3.length >= 100 + 64 + 9);

  // ClientHelloOuter MUST NOT leak realHost anywhere in plaintext, and MUST decrypt with ClientHelloOuterAAD
  const kp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const echCfg = encodeEchConfig({
    configId: 42,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: kp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    maximumNameLength: 64,
    publicName: 'cloudflare-ech.com',
  });
  const list = encodeEchConfigList([echCfg]);
  const selected = selectEchConfig(list);
  const hpkeInfo = Buffer.concat([Buffer.from('tls ech\0', 'ascii'), selected.config.rawConfig]);
  const { enc, sealer } = setupBaseS(selected.suite, kp.publicKey, hpkeInfo);

  const dummyShare = {
    group: TLS_GROUP_X25519,
    publicKey: Buffer.alloc(32, 0x55),
    computeSharedSecret: () => Buffer.alloc(32, 0x77),
  };
  const sessionId = crypto.randomBytes(32);
  const pair = buildEchClientHelloPair({
    selected,
    sealer,
    enc,
    realHost: 'secret-tunnel.neruton.example',
    innerRandom: crypto.randomBytes(32),
    outerRandom: crypto.randomBytes(32),
    legacySessionId: sessionId,
    innerKeyShare: dummyShare,
    outerKeyShare: dummyShare,
  });

  assert.equal(
    pair.clientHelloOuterMsg.includes(Buffer.from('secret-tunnel.neruton.example', 'ascii')),
    false,
    'realHost MUST NOT appear in plaintext ClientHelloOuter',
  );
  assert.equal(
    pair.clientHelloOuterMsg.includes(Buffer.from('cloudflare-ech.com', 'ascii')),
    true,
    'public_name MUST appear in ClientHelloOuter',
  );
  assert.equal(pair.encodedClientHelloInner.length % 32, 0);

  // Decrypt on server side using ClientHelloOuterAAD
  const opener = setupBaseR(selected.suite, enc, kp.privateKey, hpkeInfo);
  const parsedOuter = parseClientHelloBody(pair.clientHelloOuterMsg.subarray(4));
  const decrypted = opener.open(pair.clientHelloOuterAad, parsedOuter.echExt.payload);
  assert.deepEqual(decrypted, pair.encodedClientHelloInner);
  const reconstructed = reconstructClientHelloInner(decrypted, sessionId);
  assert.equal(reconstructed.parsed.sni, 'secret-tunnel.neruton.example');
  assert.deepEqual(reconstructed.rawMsg, pair.clientHelloInnerMsg);

  // TLS 1.3 record layer across all 3 suites: padding strip, all-zero rejection, overflow, tampered tag, KeyUpdate
  for (const sid of [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256]) {
    const spec = getCipherSuiteSpec(sid);
    const secret = crypto.randomBytes(spec.hashLen);
    const encCipher = new Tls13RecordCipher(spec, secret);
    const decCipher = new Tls13RecordCipher(spec, secret);

    const rec = encCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.from('hello-tls13'), 13);
    const out = decCipher.decryptRecord(rec.subarray(0, 5), rec.subarray(5));
    assert.equal(out.contentType, TLS_CONTENT_APPLICATION_DATA);
    assert.deepEqual(out.content, Buffer.from('hello-tls13'));

    // Tampered tag -> bad_record_mac
    const bad = Buffer.from(rec);
    bad[bad.length - 1] ^= 0x01;
    assert.throws(() => decCipher.decryptRecord(bad.subarray(0, 5), bad.subarray(5)), /bad_record_mac/i);

    // Plaintext > 16384 rejected
    assert.throws(
      () => encCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.alloc(TLS_MAX_PLAINTEXT + 1)),
      /exceeds 16384/,
    );

    // KeyUpdate rotation keeps sender/receiver synchronized
    encCipher.rotateKeys();
    decCipher.rotateKeys();
    assert.equal(encCipher.seq, 0n);
    assert.equal(decCipher.seq, 0n);
    const rec2 = encCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.from('post-keyupdate'));
    const out2 = decCipher.decryptRecord(rec2.subarray(0, 5), rec2.subarray(5));
    assert.deepEqual(out2.content, Buffer.from('post-keyupdate'));

    // All-zero inner plaintext (type=0) rejected with unexpected_message
    const zeroRec = encCipher.encryptRecord(0, Buffer.alloc(4, 0));
    assert.throws(
      () => decCipher.decryptRecord(zeroRec.subarray(0, 5), zeroRec.subarray(5)),
      /missing content type/i,
    );
  }
});

// ===========================================================================
// 2. Strict X.509 Chain & Identity Verification Tests (Node >=18 safe)
// ===========================================================================

test('Strict X.509 verification: valid 3-cert chain, wildcard/IP SAN, wrong host, expired, non-CA, wrong EKU, untrusted, cycle guard', () => {
  const pki = buildSyntheticPki();
  try {
    // 1. Valid 3-cert chain (leaf -> intermediate -> root)
    const leaf = verifyX509Chain([pki.leafRsa.certDer, pki.interDer], 'secret.neruton.test', {
      ca: pki.rootPem,
    });
    assert.match(leaf.subject, /secret\.neruton\.test/);

    // Wildcard & IP SAN match
    verifyX509Chain([pki.leafRsa.certDer, pki.interDer], 'sub.wild.neruton.test', { ca: pki.rootPem });
    verifyX509Chain([pki.leafRsa.certDer, pki.interDer], '127.0.0.1', { ca: pki.rootPem });

    // 2. Wrong hostname rejected
    assert.throws(
      () => verifyX509Chain([pki.leafRsa.certDer, pki.interDer], 'evil.neruton.test', { ca: pki.rootPem }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_HOSTNAME_MISMATCH',
    );

    // 3. Expired cert rejected (simulate nowMs 60 days in future)
    assert.throws(
      () =>
        verifyX509Chain([pki.leafRsa.certDer, pki.interDer], 'secret.neruton.test', {
          ca: pki.rootPem,
          nowMs: Date.now() + 60 * 86400 * 1000,
        }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_EXPIRED',
    );

    // 4. Not-yet-valid cert rejected (simulate nowMs 1 day in past)
    assert.throws(
      () =>
        verifyX509Chain([pki.leafRsa.certDer, pki.interDer], 'secret.neruton.test', {
          ca: pki.rootPem,
          nowMs: Date.now() - 2 * 86400 * 1000,
        }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_NOT_YET_VALID',
    );

    // 5. Non-CA issuer (leafRsa has CA:FALSE) attempting to act as intermediate CA -> REJECTED!
    assert.throws(
      () =>
        verifyX509Chain([pki.childOfNonCa.certDer, pki.leafRsa.certDer, pki.interDer], 'forged.neruton.test', {
          ca: pki.rootPem,
        }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_UNTRUSTED',
    );

    // 6. Wrong EKU (clientAuth only, missing serverAuth) -> REJECTED!
    assert.throws(
      () => verifyX509Chain([pki.leafClientEku.certDer, pki.interDer], 'secret.neruton.test', { ca: pki.rootPem }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_BAD_EKU',
    );

    // 7. Untrusted root -> REJECTED!
    assert.throws(
      () => verifyX509Chain([pki.leafUntrusted.certDer], 'secret.neruton.test', { ca: pki.rootPem }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_UNTRUSTED',
    );

    // 8. Cyclic intermediate chain (A -> B -> A) terminates cleanly without stack overflow!
    assert.throws(
      () =>
        verifyX509Chain([pki.leafCyc.certDer, pki.cycADer, pki.cycBDer], 'secret.neruton.test', {
          ca: pki.rootPem,
        }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_UNTRUSTED',
    );

    // 9. CN-only certificate (no SAN extension) -> REJECTED!
    assert.throws(
      () => verifyX509Chain([pki.leafCnOnly.certDer, pki.interDer], 'secret.neruton.test', { ca: pki.rootPem }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_HOSTNAME_MISMATCH',
    );

    // 10. BasicConstraints pathLenConstraint enforcement (RFC 5280 §6.1.4):
    // Root -> Inter (pathlen:0) -> SubCA (CA:TRUE) -> Leaf -> REJECTED!
    assert.throws(
      () =>
        verifyX509Chain([pki.leafUnderPathlen0.certDer, pki.subCa0Der, pki.interDer], 'pathlen.test', {
          ca: pki.rootPem,
        }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_PATHLEN_EXCEEDED',
    );

    // Root -> Inter (pathlen:1) -> SubCA (CA:TRUE) -> Leaf -> ACCEPTED!
    const validPathlen1 = verifyX509Chain(
      [pki.leafUnderPathlen1.certDer, pki.subCa1Der, pki.inter1Der],
      'pathlen.test',
      { ca: pki.rootPem },
    );
    assert.match(validPathlen1.subject, /pathlen\.test/);

    // Root (pathlen:0) -> Inter (CA:TRUE) -> Leaf -> REJECTED!
    assert.throws(
      () =>
        verifyX509Chain([pki.leafUnderRootPathlen0.certDer, pki.interR0Der], 'pathlen.test', {
          ca: pki.root0Pem,
        }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_PATHLEN_EXCEEDED',
    );
  } finally {
    pki.cleanup();
  }
});

// ===========================================================================
// 3. Full Mock RFC 9849 TLS 1.3 + ECH Handshake, HRR, KeyUpdate, Interop & Retry
// ===========================================================================

test('TLS 1.3 + ECH accepted across all 3 cipher suites, RSA-PSS/ECDSA-P256/ECDSA-P384/Ed25519, fragmented flight, NewSessionTicket, KeyUpdate, >16KiB chunking', async () => {
  const pki = buildSyntheticPki();
  const echKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const rawEchCfg = encodeEchConfig({
    configId: 11,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: echKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    maximumNameLength: 64,
    publicName: 'outer-ech.test',
  });
  const echConfigList = encodeEchConfigList([rawEchCfg]);

  const matrix = [
    {
      name: 'AES-128-GCM + RSA-PSS-SHA256 + fragmented flight + NST + KeyUpdate(requested=1)',
      cipherSuite: TLS_AES_128_GCM_SHA256,
      cert: pki.leafRsa,
      sigScheme: TLS_SIG_RSA_PSS_RSAE_SHA256,
      fragmentServerFlight: true,
      sendNewSessionTicket: true,
      keyUpdateRequest: 1,
    },
    {
      name: 'AES-256-GCM-SHA384 + ECDSA-P384-SHA384 + KeyUpdate(requested=0)',
      cipherSuite: TLS_AES_256_GCM_SHA384,
      cert: pki.leafP384,
      sigScheme: TLS_SIG_ECDSA_SECP384R1_SHA384,
      keyUpdateRequest: 0,
    },
    {
      name: 'ChaCha20-Poly1305 + Ed25519',
      cipherSuite: TLS_CHACHA20_POLY1305_SHA256,
      cert: pki.leafEd25519,
      sigScheme: TLS_SIG_ED25519,
    },
    {
      name: 'HRR secp256r1 + cookie + ECDSA-P256-SHA256',
      cipherSuite: TLS_AES_128_GCM_SHA256,
      cert: pki.leafP256,
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
      requireHrrGroup: TLS_GROUP_SECP256R1,
      requireCookie: Buffer.from('hrr-cookie-token-1234'),
    },
  ];

  try {
    for (const tc of matrix) {
      const srv = await startMockTls13EchServer({
        acceptEch: true,
        configId: 11,
        rawEchConfig: rawEchCfg,
        echPrivateKey: echKp.privateKey,
        cipherSuite: tc.cipherSuite,
        fragmentServerFlight: tc.fragmentServerFlight,
        sendNewSessionTicket: tc.sendNewSessionTicket,
        keyUpdateRequest: tc.keyUpdateRequest,
        requireHrrGroup: tc.requireHrrGroup,
        requireCookie: tc.requireCookie,
        innerCert: {
          keyPem: tc.cert.keyPem,
          chainDers: [tc.cert.certDer, pki.interDer],
          sigScheme: tc.sigScheme,
        },
        outerCert: {
          keyPem: pki.leafOuter.keyPem,
          chainDers: [pki.leafOuter.certDer, pki.interDer],
          sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
        },
      });

      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, {
          realHost: 'secret.neruton.test',
          echConfigList,
          ca: pki.rootPem,
        });

        assert.equal(duplex.echStatus, 'accepted', tc.name);
        assert.equal(duplex.outerSni, 'outer-ech.test', tc.name);
        assert.equal(duplex.authorized, true, tc.name);
        assert.equal(duplex.getProtocol(), 'TLSv1.3', tc.name);
        assert.equal(duplex.alpnProtocol, 'http/1.1', tc.name);

        // Exercise >16 KiB outbound chunking + echo roundtrip + KeyUpdate handling
        const payload = crypto.randomBytes(40 * 1024);
        const echoRoundTrip = (msg) =>
          new Promise((resolve, reject) => {
            const chunks = [];
            let total = 0;
            const onData = (c) => {
              chunks.push(c);
              total += c.length;
              if (total >= msg.length) {
                duplex.off('data', onData);
                duplex.off('error', onErr);
                resolve(Buffer.concat(chunks));
              }
            };
            const onErr = (e) => {
              duplex.off('data', onData);
              reject(e);
            };
            duplex.on('data', onData);
            duplex.once('error', onErr);
            duplex.write(msg);
          });

        const echoed = await echoRoundTrip(payload);
        assert.deepEqual(echoed, payload, `${tc.name}: echoed payload mismatch`);

        // Second round-trip after KeyUpdate guarantees bidirectional traffic works on rotated keys!
        const postKu = Buffer.from(`post-keyupdate:${tc.name}`);
        const echoed2 = await echoRoundTrip(postKu);
        assert.deepEqual(echoed2, postKu, `${tc.name}: post-KeyUpdate echo mismatch`);

        const conn = srv.state.connections[0];
        assert.equal(conn.outerSni, 'outer-ech.test');
        assert.equal(conn.innerSni, 'secret.neruton.test');
        assert.equal(conn.echAccepted, true);
        if (tc.requireHrrGroup) assert.equal(conn.hrrSent, true);
        if (tc.keyUpdateRequest === 1) assert.equal(conn.keyUpdateReceived, true);

        // Clean close_notify & teardown
        duplex.end();
        await new Promise((r) => setTimeout(r, 30));
        duplex.destroy();
      } finally {
        await srv.close();
      }
    }
  } finally {
    pki.cleanup();
  }
});

test('TLS 1.3 + ECH rejects tampered CertificateVerify and tampered server Finished', async () => {
  const pki = buildSyntheticPki();
  const echKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const rawEchCfg = encodeEchConfig({
    configId: 12,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: echKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    publicName: 'outer-ech.test',
  });
  const echConfigList = encodeEchConfigList([rawEchCfg]);

  try {
    // 1. Tampered CertificateVerify (rejected both with strict verify AND with noTlsVerify: true!)
    const srvCv = await startMockTls13EchServer({
      acceptEch: true,
      configId: 12,
      rawEchConfig: rawEchCfg,
      echPrivateKey: echKp.privateKey,
      tamperCertVerify: true,
      innerCert: {
        keyPem: pki.leafRsa.keyPem,
        chainDers: [pki.leafRsa.certDer, pki.interDer],
        sigScheme: TLS_SIG_RSA_PSS_RSAE_SHA256,
      },
      outerCert: {
        keyPem: pki.leafOuter.keyPem,
        chainDers: [pki.leafOuter.certDer, pki.interDer],
        sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
      },
    });
    try {
      for (const noTlsVerify of [false, true]) {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srvCv.port }]);
        await assert.rejects(
          () =>
            performTls13EchHandshake(socket, {
              realHost: 'secret.neruton.test',
              echConfigList,
              ca: pki.rootPem,
              noTlsVerify,
            }),
          (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_VERIFY_FAILED',
        );
      }
    } finally {
      await srvCv.close();
    }

    // 2. Tampered server Finished (rejected both with strict verify AND with noTlsVerify: true!)
    const srvFin = await startMockTls13EchServer({
      acceptEch: true,
      configId: 12,
      rawEchConfig: rawEchCfg,
      echPrivateKey: echKp.privateKey,
      tamperServerFinished: true,
      innerCert: {
        keyPem: pki.leafP256.keyPem,
        chainDers: [pki.leafP256.certDer, pki.interDer],
        sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
      },
      outerCert: {
        keyPem: pki.leafOuter.keyPem,
        chainDers: [pki.leafOuter.certDer, pki.interDer],
        sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
      },
    });
    try {
      for (const noTlsVerify of [false, true]) {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srvFin.port }]);
        await assert.rejects(
          () =>
            performTls13EchHandshake(socket, {
              realHost: 'secret.neruton.test',
              echConfigList,
              ca: pki.rootPem,
              noTlsVerify,
            }),
          (e) => e instanceof TlsProtocolError && e.code === 'TLS_FINISHED_FAILED',
        );
      }
    } finally {
      await srvFin.close();
    }
  } finally {
    pki.cleanup();
  }
});

test('RFC 9849 ECH rejection: verifies outer cert, sends fatal ech_required (0x79) with ZERO app data, retries once with retry_configs, and rejects forged outer cert', async () => {
  const pki = buildSyntheticPki();
  const realKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const staleKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);

  const realEchCfg = encodeEchConfig({
    configId: 21,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: realKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    maximumNameLength: 64,
    publicName: 'outer-ech.test',
  });
  const realEchList = encodeEchConfigList([realEchCfg]);

  const staleEchCfg = encodeEchConfig({
    configId: 99, // Stale config_id -> server rejects and supplies retry_configs = realEchList
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: staleKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    maximumNameLength: 64,
    publicName: 'outer-ech.test',
  });
  const staleEchList = encodeEchConfigList([staleEchCfg]);

  const srv = await startMockTls13EchServer({
    acceptEch: true,
    configId: 21,
    rawEchConfig: realEchCfg,
    echPrivateKey: realKp.privateKey,
    retryConfigs: realEchList,
    innerCert: {
      keyPem: pki.leafP256.keyPem,
      chainDers: [pki.leafP256.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
    outerCert: {
      keyPem: pki.leafOuter.keyPem,
      chainDers: [pki.leafOuter.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
  });

  // Malicious server returning wrong cert (for secret.neruton.test instead of outer-ech.test) on ECH rejection!
  const forgedOuterSrv = await startMockTls13EchServer({
    acceptEch: false,
    configId: 21,
    rawEchConfig: realEchCfg,
    echPrivateKey: realKp.privateKey,
    retryConfigs: realEchList,
    innerCert: {
      keyPem: pki.leafP256.keyPem,
      chainDers: [pki.leafP256.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
    outerCert: {
      // Wrong cert for public_name 'outer-ech.test'
      keyPem: pki.leafP256.keyPem,
      chainDers: [pki.leafP256.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
  });

  try {
    // 1. Stale config -> rejection on conn #1 (fatal alert 0x79, 0 app bytes) -> retry on conn #2 succeeds!
    const warns = [];
    const res = await connectTls13EchWithRetry({
      realHost: 'secret.neruton.test',
      echConfigList: staleEchList,
      connectTcp: () => connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]),
      ca: pki.rootPem,
      onWarn: (m) => warns.push(m),
    });

    assert.equal(res.echStatus, 'accepted');
    assert.equal(res.echRetried, true);
    assert.equal(res.outerSni, 'outer-ech.test');
    assert.equal(warns.length, 1);
    assert.match(warns[0], /retry_configs/);

    assert.equal(srv.state.connections.length, 2, 'must open fresh TCP socket for 1-shot retry');
    // Connection #1: rejected, sent fatal alert ech_required (0x79), ZERO app bytes!
    assert.equal(srv.state.connections[0].echAccepted, false);
    assert.equal(srv.state.connections[0].appBytesReceived.length, 0);
    assert.deepEqual(srv.state.connections[0].alertsReceived, [
      { level: 2, desc: TLS_ALERT_ECH_REQUIRED },
    ]);
    // Connection #2: accepted!
    assert.equal(srv.state.connections[1].echAccepted, true);
    assert.equal(srv.state.connections[1].innerSni, 'secret.neruton.test');

    // Verify safe _destroy with error triggers NO uncaughtException on underlying raw socket
    let uncaught = null;
    const onUncaught = (e) => {
      uncaught = e;
    };
    process.on('uncaughtException', onUncaught);
    try {
      res.duplex.on('error', () => {});
      res.duplex.destroy(new Error('SYNTHETIC_DESTROY'));
      await new Promise((r) => setTimeout(r, 30));
      assert.equal(uncaught, null);
      assert.equal(res.duplex.raw.destroyed, true);
    } finally {
      process.off('uncaughtException', onUncaught);
    }

    // 2. Forged outer cert on rejection MUST fail cert verification and NEVER retry with untrusted retry_configs!
    await assert.rejects(
      () =>
        connectTls13EchWithRetry({
          realHost: 'secret.neruton.test',
          echConfigList: staleEchList,
          connectTcp: () => connectTcpWithFailover([{ host: '127.0.0.1', port: forgedOuterSrv.port }]),
          ca: pki.rootPem,
        }),
      (e) => e instanceof TlsProtocolError && e.code === 'TLS_CERT_HOSTNAME_MISMATCH',
    );
    assert.equal(forgedOuterSrv.state.connections.length, 1, 'must NEVER retry after unauthenticated outer cert');
  } finally {
    await srv.close();
    await forgedOuterSrv.close();
    pki.cleanup();
  }
});

test('planStealthTls selects true TLS 1.3 ECH in auto/ech modes when ECHConfigList is available', () => {
  const kp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const echList = encodeEchConfigList([
    encodeEchConfig({
      configId: 1,
      kemId: HPKE_KEM_X25519_SHA256,
      publicKey: kp.publicKey,
      cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
      publicName: 'cloudflare-ech.com',
    }),
  ]);

  // auto + DoH ECH -> uses ECH with fallback enabled
  const autoPlan = planStealthTls({
    wsUrl: new URL('wss://neruton.moer.eu.org/_neruton/tunnel'),
    sniMode: 'auto',
    dohEchConfigs: [echList],
  });
  assert.equal(autoPlan.effectiveSniMode, 'ech');
  assert.equal(autoPlan.useEch, true);
  assert.equal(autoPlan.echAllowFallback, true);
  assert.equal(autoPlan.outerSni, 'cloudflare-ech.com');

  // ech + explicit base64 echConfig -> uses ECH with fallback disabled
  const strictPlan = planStealthTls({
    wsUrl: new URL('wss://neruton.moer.eu.org/_neruton/tunnel'),
    sniMode: 'ech',
    echConfig: echList.toString('base64'),
  });
  assert.equal(strictPlan.effectiveSniMode, 'ech');
  assert.equal(strictPlan.useEch, true);
  assert.equal(strictPlan.echAllowFallback, false);
  assert.equal(strictPlan.outerSni, 'cloudflare-ech.com');
});

test('End-to-end Tunnel connect() over true TLS 1.3 ECH + WebSocket + Yamux with TransportInfo reporting', async () => {
  const pki = buildSyntheticPki();
  const echKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const rawEchCfg = encodeEchConfig({
    configId: 5,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: echKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    maximumNameLength: 64,
    publicName: 'outer-ech.test',
  });
  const echConfigList = encodeEchConfigList([rawEchCfg]);

  // Minimal HTTP/1.1 WebSocket upgrade handler fed over our mock TLS 1.3 ECH server!
  const wss = new WebSocketServer({ noServer: true });
  let seenAuthHeader = null;
  const mockEchGateway = await startMockTls13EchServer({
    acceptEch: true,
    configId: 5,
    rawEchConfig: rawEchCfg,
    echPrivateKey: echKp.privateKey,
    sendNewSessionTicket: true,
    innerCert: {
      keyPem: pki.leafP256.keyPem,
      chainDers: [pki.leafP256.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
    outerCert: {
      keyPem: pki.leafOuter.keyPem,
      chainDers: [pki.leafOuter.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
    onAppData: (() => {
      let upgraded = false;
      let httpBuf = Buffer.alloc(0);
      let bridge = null;
      return (chunk, sendReply) => {
        if (!upgraded) {
          httpBuf = Buffer.concat([httpBuf, chunk]);
          const hdrEnd = httpBuf.indexOf('\r\n\r\n');
          if (hdrEnd === -1) return;
          const reqText = httpBuf.subarray(0, hdrEnd).toString('utf8');
          const keyMatch = reqText.match(/Sec-WebSocket-Key:\s*([^\r\n]+)/i);
          const authMatch = reqText.match(/Authorization:\s*([^\r\n]+)/i);
          seenAuthHeader = authMatch ? authMatch[1].trim() : null;
          upgraded = true;

          const fakeReq = {
            method: 'GET',
            url: '/_neruton/tunnel',
            headers: {
              upgrade: 'websocket',
              connection: 'Upgrade',
              'sec-websocket-key': keyMatch[1].trim(),
              'sec-websocket-version': '13',
            },
          };
          const wsProtoSock = new Duplex({
            read() {},
            write(c, _enc, cb) {
              sendReply(Buffer.from(c));
              cb();
            },
          });
          wsProtoSock.setNoDelay = () => wsProtoSock;
          wsProtoSock.setTimeout = () => wsProtoSock;
          wss.handleUpgrade(fakeReq, wsProtoSock, httpBuf.subarray(hdrEnd + 4), (ws) => {
            ws.once('message', () => {
              ws.send(
                JSON.stringify({
                  ok: true,
                  tunnel_id: 'tid-ech',
                  prefix: 'ech-demo',
                  public_url: 'https://ech-demo.secret.neruton.test',
                  path_url: 'https://secret.neruton.test/t/ech-demo/',
                  preview_url: 'https://secret.neruton.test/preview/ech-demo',
                  dashboard_url: 'https://secret.neruton.test',
                  error: null,
                }),
              );
              const wsStream = new WsByteStream(ws);
              new YamuxSession(wsStream, { mode: 'client' });
            });
          });
          bridge = wsProtoSock;
          return;
        }
        bridge.push(chunk);
      };
    })(),
  });

  // Mock DoH server returning 127.0.0.1 + HTTPS record carrying echConfigList
  const https = await import('node:https');
  const dohSrv = https.createServer({ key: pki.leafRsa.keyPem, cert: Buffer.concat([pki.leafRsa.certPem, pki.interPem]) }, (req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const q = Buffer.concat(chunks);
      let pos = 12;
      while (pos < q.length && q[pos] !== 0) pos += 1 + q[pos];
      const qtype = q.readUInt16BE(pos + 1);
      const question = q.subarray(12);
      const hdr = Buffer.alloc(12);
      hdr.writeUInt16BE(q.readUInt16BE(0), 0);
      hdr.writeUInt16BE(0x8180, 2);
      hdr.writeUInt16BE(1, 4);

      const records = [];
      if (qtype === 1) {
        records.push({ type: 1, rdata: Buffer.from([127, 0, 0, 1]) });
      } else if (qtype === 65) {
        const paramHdr = Buffer.alloc(4);
        paramHdr.writeUInt16BE(5, 0); // SvcParam ech=5
        paramHdr.writeUInt16BE(echConfigList.length, 2);
        const rdata = Buffer.concat([u16(1), Buffer.from([0x00]), paramHdr, echConfigList]);
        records.push({ type: 65, rdata });
      }
      hdr.writeUInt16BE(records.length, 6);
      const ans = records.map((r) => {
        const meta = Buffer.alloc(10);
        meta.writeUInt16BE(r.type, 0);
        meta.writeUInt16BE(1, 2);
        meta.writeUInt32BE(300, 4);
        meta.writeUInt16BE(r.rdata.length, 8);
        return Buffer.concat([Buffer.from([0xc0, 0x0c]), meta, r.rdata]);
      });
      res.writeHead(200, { 'Content-Type': 'application/dns-message' });
      res.end(Buffer.concat([hdr, question, ...ans]));
    });
  });
  await new Promise((r) => dohSrv.listen(0, '127.0.0.1', r));
  const dohUrl = `https://127.0.0.1:${dohSrv.address().port}/dns-query`;

  try {
    const tunnel = await connect({
      url: 3000,
      server: `https://secret.neruton.test:${mockEchGateway.port}`,
      token: 'ntk_ech_secret_token',
      doh: dohUrl,
      sniMode: 'auto',
      ca: [pki.rootPem, pki.interPem],
      keepaliveIntervalMs: 0,
    });

    assert.equal(tunnel.connected, true);
    assert.equal(seenAuthHeader, 'Bearer ntk_ech_secret_token');
    assert.equal(tunnel.transportInfo.effectiveSniMode, 'ech');
    assert.equal(tunnel.transportInfo.echStatus, 'accepted');
    assert.equal(tunnel.transportInfo.outerSni, 'outer-ech.test');
    assert.equal(tunnel.transportInfo.tlsProtocol, 'TLSv1.3');
    assert.equal(tunnel.transportInfo.tlsAuthorized, true);
    assert.match(tunnel.transportInfo.summary, /DoH \+ ECH \(outer: outer-ech\.test\)/);

    assert.equal(mockEchGateway.state.connections[0].outerSni, 'outer-ech.test');
    assert.equal(mockEchGateway.state.connections[0].innerSni, 'secret.neruton.test');
    assert.equal(mockEchGateway.state.connections[0].echAccepted, true);

    await tunnel.close();
  } finally {
    for (const c of wss.clients) c.terminate();
    await new Promise((r) => wss.close(r));
    await new Promise((r) => {
      dohSrv.closeAllConnections?.();
      dohSrv.close(r);
    });
    await mockEchGateway.close();
    pki.cleanup();
  }
});

test('sniMode: ech fails fast with ECH_REJECTED without retrying reconnect loop; sniMode: auto falls back to fragmentation with echStatus=fallback', async () => {
  const pki = buildSyntheticPki();
  const echKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const rawEchCfg = encodeEchConfig({
    configId: 33,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: echKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    publicName: 'outer-ech.test',
  });
  const echConfigList = encodeEchConfigList([rawEchCfg]);

  // Server that ALWAYS rejects ECH (with no retry_configs)
  const rejectSrv = await startMockTls13EchServer({
    acceptEch: false,
    configId: 33,
    rawEchConfig: rawEchCfg,
    echPrivateKey: echKp.privateKey,
    innerCert: {
      keyPem: pki.leafP256.keyPem,
      chainDers: [pki.leafP256.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
    outerCert: {
      keyPem: pki.leafOuter.keyPem,
      chainDers: [pki.leafOuter.certDer, pki.interDer],
      sigScheme: TLS_SIG_ECDSA_SECP256R1_SHA256,
    },
  });

  // Also test a real Node HTTPS gateway that doesn't speak ECH at all (so after ECH rejection -> auto fallback -> ClientHello fragmentation succeeds!)
  const https = await import('node:https');
  const tls = await import('node:tls');
  const wss = new WebSocketServer({ noServer: true });
  const fallbackGw = https.createServer({
    key: pki.leafOuter.keyPem,
    cert: Buffer.concat([pki.leafOuter.certPem, pki.interPem]),
    SNICallback: (sn, cb) => {
      const c = sn === 'outer-ech.test' ? pki.leafOuter : pki.leafP256;
      cb(
        null,
        tls.createSecureContext({
          key: c.keyPem,
          cert: Buffer.concat([c.certPem, pki.interPem]),
        }),
      );
    },
  });
  fallbackGw.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.once('message', () => {
        ws.send(
          JSON.stringify({
            ok: true,
            tunnel_id: 'tid-fb',
            prefix: 'fb-demo',
            public_url: 'https://fb-demo.secret.neruton.test',
            path_url: 'https://secret.neruton.test/t/fb-demo/',
            preview_url: 'https://secret.neruton.test/preview/fb-demo',
            dashboard_url: 'https://secret.neruton.test',
            error: null,
          }),
        );
        new YamuxSession(new WsByteStream(ws), { mode: 'client' });
      });
    });
  });
  await new Promise((r) => fallbackGw.listen(0, '127.0.0.1', r));
  const fbPort = fallbackGw.address().port;

  // Mock DoH server returning 127.0.0.1 + ECHConfigList
  const dohSrv = https.createServer(
    { key: pki.leafRsa.keyPem, cert: Buffer.concat([pki.leafRsa.certPem, pki.interPem]) },
    (req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const q = Buffer.concat(chunks);
        let pos = 12;
        while (pos < q.length && q[pos] !== 0) pos += 1 + q[pos];
        const qtype = q.readUInt16BE(pos + 1);
        const question = q.subarray(12);
        const hdr = Buffer.alloc(12);
        hdr.writeUInt16BE(q.readUInt16BE(0), 0);
        hdr.writeUInt16BE(0x8180, 2);
        hdr.writeUInt16BE(1, 4);
        const records = [];
        if (qtype === 1) {
          records.push({ type: 1, rdata: Buffer.from([127, 0, 0, 1]) });
        } else if (qtype === 65) {
          const paramHdr = Buffer.alloc(4);
          paramHdr.writeUInt16BE(5, 0);
          paramHdr.writeUInt16BE(echConfigList.length, 2);
          records.push({
            type: 65,
            rdata: Buffer.concat([u16(1), Buffer.from([0x00]), paramHdr, echConfigList]),
          });
        }
        hdr.writeUInt16BE(records.length, 6);
        const ans = records.map((r) => {
          const meta = Buffer.alloc(10);
          meta.writeUInt16BE(r.type, 0);
          meta.writeUInt16BE(1, 2);
          meta.writeUInt32BE(300, 4);
          meta.writeUInt16BE(r.rdata.length, 8);
          return Buffer.concat([Buffer.from([0xc0, 0x0c]), meta, r.rdata]);
        });
        res.writeHead(200, { 'Content-Type': 'application/dns-message' });
        res.end(Buffer.concat([hdr, question, ...ans]));
      });
    },
  );
  await new Promise((r) => dohSrv.listen(0, '127.0.0.1', r));
  const dohUrl = `https://127.0.0.1:${dohSrv.address().port}/dns-query`;

  try {
    // 1. Strict sniMode: 'ech' rejects with ECH_REJECTED and ZERO reconnect retries!
    let reconnects = 0;
    await assert.rejects(
      () =>
        connect({
          url: 3000,
          server: `https://secret.neruton.test:${rejectSrv.port}`,
          doh: dohUrl,
          sniMode: 'ech',
          ca: [pki.rootPem, pki.interPem],
          retryInitialConnect: true,
          onReconnecting: () => {
            reconnects += 1;
          },
          keepaliveIntervalMs: 0,
        }),
      (e) => e instanceof EchRejectedError && e.code === 'ECH_REJECTED',
    );
    assert.equal(reconnects, 0, 'ECH_REJECTED in strict ech mode must fail fast without reconnecting');

    // 2. sniMode: 'auto' with DoH ECH against non-ECH HTTPS server (rejects ECH with authenticated outer cert) -> warns & falls back to fragmentation!
    const warnings = [];
    const tFb = await connect({
      url: 3000,
      server: `https://secret.neruton.test:${fbPort}`,
      doh: dohUrl,
      sniMode: 'auto',
      ca: [pki.rootPem, pki.interPem],
      onWarning: (m) => warnings.push(m),
      keepaliveIntervalMs: 0,
    });
    assert.equal(tFb.connected, true);
    assert.equal(tFb.transportInfo.echStatus, 'fallback');
    assert.equal(tFb.transportInfo.effectiveSniMode, 'fragment');
    assert.equal(tFb.transportInfo.fragmented, true);
    assert.ok(warnings.some((w) => /falling back to ClientHello TCP fragmentation/i.test(w)));
    await tFb.close();
  } finally {
    for (const c of wss.clients) c.terminate();
    await new Promise((r) => wss.close(r));
    await new Promise((r) => {
      fallbackGw.closeAllConnections?.();
      fallbackGw.close(r);
    });
    await new Promise((r) => {
      dohSrv.closeAllConnections?.();
      dohSrv.close(r);
    });
    await rejectSrv.close();
    pki.cleanup();
  }
});

// ===========================================================================
// 4. Adversarial TLS 1.3 + ECH Security Regression Suite (RFC 8446 & RFC 9849)
// ===========================================================================

test('Security regressions: post-HS plaintext alert/CCS rejection, key-change boundaries, interleaving, re-entrant destroy, HRR group enforcement, unsolicited extensions, and record overflow', async () => {
  const pki = buildSyntheticPki();
  const echKp = generateHpkeKeyPair(HPKE_KEM_X25519_SHA256);
  const rawEchCfg = encodeEchConfig({
    configId: 77,
    kemId: HPKE_KEM_X25519_SHA256,
    publicKey: echKp.publicKey,
    cipherSuites: [{ kdfId: HPKE_KDF_HKDF_SHA256, aeadId: HPKE_AEAD_AES_128_GCM }],
    maximumNameLength: 64,
    publicName: 'outer-ech.test',
  });
  const echConfigList = encodeEchConfigList([rawEchCfg]);

  // Helper: start a one-shot adversarial TCP server with full control over raw bytes & ciphers
  const runAdversarialServer = (handler) =>
    new Promise((resolve) => {
      const sockets = new Set();
      const server = net.createServer((sock) => {
        sockets.add(sock);
        sock.once('close', () => sockets.delete(sock));
        sock.on('error', () => {});
        let buf = Buffer.alloc(0);
        let wake = null;
        let ended = false;
        sock.on('data', (c) => {
          buf = Buffer.concat([buf, c]);
          const fn = wake;
          wake = null;
          fn?.();
        });
        sock.on('close', () => {
          ended = true;
          const fn = wake;
          wake = null;
          fn?.();
        });
        const readRec = async () => {
          while (buf.length < 5) {
            if (ended) throw new Error('eof');
            await new Promise((r) => { wake = r; });
          }
          const type = buf[0];
          const len = buf.readUInt16BE(3);
          while (buf.length < 5 + len) {
            if (ended) throw new Error('eof');
            await new Promise((r) => { wake = r; });
          }
          const header = Buffer.from(buf.subarray(0, 5));
          const payload = Buffer.from(buf.subarray(5, 5 + len));
          buf = buf.subarray(5 + len);
          return { type, header, payload };
        };
        Promise.resolve(handler(sock, readRec)).catch(() => {
          if (!sock.destroyed) sock.destroy();
        });
      });
      server.listen(0, '127.0.0.1', () => {
        resolve({
          port: server.address().port,
          close: () =>
            new Promise((done) => {
              for (const s of sockets) if (!s.destroyed) s.destroy();
              server.close(() => done());
            }),
        });
      });
    });

  // Helper: perform a valid server-side TLS 1.3 + ECH handshake with customizable hooks
  const doServerHandshake = async (sock, readRec, opts = {}) => {
    const suite = getCipherSuiteSpec(TLS_AES_128_GCM_SHA256);
    const hpkeSuite = {
      kemId: HPKE_KEM_X25519_SHA256,
      kdfId: HPKE_KDF_HKDF_SHA256,
      aeadId: HPKE_AEAD_AES_128_GCM,
    };
    const hpkeInfo = Buffer.concat([Buffer.from('tls ech\0', 'ascii'), rawEchCfg]);
    const ch1Rec = await readRec();
    const ch1OuterMsg = ch1Rec.payload;
    const ch1OuterBody = ch1OuterMsg.subarray(4);
    const ch1Outer = parseClientHelloBody(ch1OuterBody);
    const aad1 = Buffer.from(ch1OuterBody);
    aad1.fill(0, ch1Outer.echPayloadOffset, ch1Outer.echPayloadOffset + ch1Outer.echPayloadLen);
    const opener = setupBaseR(hpkeSuite, ch1Outer.echExt.enc, echKp.privateKey, hpkeInfo);
    const dec1 = reconstructClientHelloInner(opener.open(aad1, ch1Outer.echExt.payload), ch1Outer.sessionId);
    let innerParsed = dec1.parsed;
    let transcript = [dec1.rawMsg];
    const innerRandom = dec1.parsed.random;

    if (opts.sendHrr) {
      const hrrExts = [ext(TLS_EXT_SUPPORTED_VERSIONS, u16(0x0304))];
      if (opts.hrrGroup !== undefined) hrrExts.push(ext(TLS_EXT_KEY_SHARE, u16(opts.hrrGroup)));
      if (opts.hrrCookie) hrrExts.push(ext(TLS_EXT_COOKIE, Buffer.concat([u16(opts.hrrCookie.length), opts.hrrCookie])));
      if (opts.hrrExtraExt) hrrExts.push(opts.hrrExtraExt);
      if (opts.hrrAcceptEch !== false) hrrExts.push(ext(TLS_EXT_ECH, Buffer.alloc(8)));
      const hrrExtsBuf = Buffer.concat(hrrExts);
      const hrrBody = Buffer.concat([
        Buffer.from([0x03, 0x03]),
        TLS_HRR_RANDOM,
        Buffer.from([ch1Outer.sessionId.length]),
        ch1Outer.sessionId,
        u16(suite.id),
        Buffer.from([0x00]),
        u16(hrrExtsBuf.length),
        hrrExtsBuf,
      ]);
      const hrrMsg = wrapHs(TLS_HS_SERVER_HELLO, hrrBody);
      if (opts.hrrAcceptEch !== false) {
        const off = hrrMsg.length - 8;
        computeHrrEchAcceptConfirmation(suite.hashAlg, innerRandom, dec1.rawMsg, hrrMsg, off).copy(hrrMsg, off);
      }
      const msgHash = Buffer.concat([
        Buffer.from([TLS_HS_MESSAGE_HASH, 0x00, 0x00, suite.hashLen]),
        tlsHash(suite.hashAlg, dec1.rawMsg),
      ]);
      transcript = [msgHash, hrrMsg];
      const payload = opts.coalesceAfterHrr ? Buffer.concat([hrrMsg, wrapHs(TLS_HS_ENCRYPTED_EXTENSIONS, u16(0))]) : hrrMsg;
      sock.write(wrapRec(TLS_CONTENT_HANDSHAKE, payload));
      if (opts.stopAfterHrr) return null;

      const ch2Rec = await readRec();
      const ch2OuterMsg = ch2Rec.payload;
      const ch2OuterBody = ch2OuterMsg.subarray(4);
      const ch2Outer = parseClientHelloBody(ch2OuterBody);
      const aad2 = Buffer.from(ch2OuterBody);
      aad2.fill(0, ch2Outer.echPayloadOffset, ch2Outer.echPayloadOffset + ch2Outer.echPayloadLen);
      const dec2 = reconstructClientHelloInner(opener.open(aad2, ch2Outer.echExt.payload), ch2Outer.sessionId);
      innerParsed = dec2.parsed;
      transcript.push(dec2.rawMsg);
    }

    const group = opts.shGroupOverride ?? opts.hrrGroup ?? TLS_GROUP_X25519;
    const clientPub = innerParsed.keyShares.get(group) ?? dec1.parsed.keyShares.get(group);
    let serverPub;
    let sharedSecret;
    if (group === TLS_GROUP_X25519) {
      const pair = crypto.generateKeyPairSync('x25519');
      serverPub = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
      const peerObj = crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, clientPub]), format: 'der', type: 'spki' });
      sharedSecret = crypto.diffieHellman({ privateKey: pair.privateKey, publicKey: peerObj });
    } else {
      const ecdh = crypto.createECDH('prime256v1');
      ecdh.generateKeys();
      serverPub = ecdh.getPublicKey(null, 'uncompressed');
      sharedSecret = ecdh.computeSecret(clientPub);
    }

    const shExtList = [
      ext(TLS_EXT_SUPPORTED_VERSIONS, u16(0x0304)),
      ext(TLS_EXT_KEY_SHARE, Buffer.concat([u16(group), u16(serverPub.length), serverPub])),
    ];
    if (opts.shExtraExt) shExtList.push(opts.shExtraExt);
    const shExtsBuf = Buffer.concat(shExtList);
    const shBody = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      crypto.randomBytes(32),
      Buffer.from([ch1Outer.sessionId.length]),
      ch1Outer.sessionId,
      u16(suite.id),
      Buffer.from([0x00]),
      u16(shExtsBuf.length),
      shExtsBuf,
    ]);
    const shMsg = wrapHs(TLS_HS_SERVER_HELLO, shBody);
    computeEchAcceptConfirmation(suite.hashAlg, innerRandom, transcript, shMsg).copy(shMsg, 30);
    transcript.push(shMsg);

    const zeroHash = Buffer.alloc(suite.hashLen);
    const emptyHash = tlsHash(suite.hashAlg, Buffer.alloc(0));
    const earlySecret = hkdfExtract(suite.hashAlg, zeroHash, zeroHash);
    const derivedEarly = deriveSecret(suite.hashAlg, earlySecret, 'derived', emptyHash);
    const hsSecret = hkdfExtract(suite.hashAlg, derivedEarly, sharedSecret);
    const shHash = tlsHash(suite.hashAlg, transcript);
    const cHsSecret = deriveSecret(suite.hashAlg, hsSecret, 'c hs traffic', shHash);
    const sHsSecret = deriveSecret(suite.hashAlg, hsSecret, 's hs traffic', shHash);
    const sHsCipher = new Tls13RecordCipher(suite, sHsSecret);
    const cHsCipher = new Tls13RecordCipher(suite, cHsSecret);

    const eeExts = [];
    if (opts.sendAlpn !== false) {
      const p = Buffer.from('http/1.1', 'ascii');
      const e = Buffer.concat([Buffer.from([p.length]), p]);
      eeExts.push(ext(TLS_EXT_ALPN, Buffer.concat([u16(e.length), e])));
    }
    if (opts.eeExtraExt) eeExts.push(opts.eeExtraExt);
    const eeExtsBuf = Buffer.concat(eeExts);
    const eeMsg = wrapHs(TLS_HS_ENCRYPTED_EXTENSIONS, Buffer.concat([u16(eeExtsBuf.length), eeExtsBuf]));
    transcript.push(eeMsg);

    const chainDers = [pki.leafP256.certDer, pki.interDer];
    const certList = Buffer.concat(chainDers.map((d) => Buffer.concat([u24(d.length), d, u16(0)])));
    const certMsg = wrapHs(TLS_HS_CERTIFICATE, Buffer.concat([Buffer.from([0x00]), u24(certList.length), certList]));
    transcript.push(certMsg);

    const preCvHash = tlsHash(suite.hashAlg, transcript);
    const sig = signCertificateVerify(pki.leafP256.keyPem, TLS_SIG_ECDSA_SECP256R1_SHA256, preCvHash);
    const cvMsg = wrapHs(TLS_HS_CERTIFICATE_VERIFY, Buffer.concat([u16(TLS_SIG_ECDSA_SECP256R1_SHA256), u16(sig.length), sig]));
    transcript.push(cvMsg);

    const preSfHash = tlsHash(suite.hashAlg, transcript);
    const sfMsg = wrapHs(TLS_HS_FINISHED, computeFinishedVerifyData(suite, sHsSecret, preSfHash));
    transcript.push(sfMsg);

    const postSfHash = tlsHash(suite.hashAlg, transcript);
    const derivedHs = deriveSecret(suite.hashAlg, hsSecret, 'derived', emptyHash);
    const masterSecret = hkdfExtract(suite.hashAlg, derivedHs, zeroHash);
    const sAppCipher = new Tls13RecordCipher(suite, deriveSecret(suite.hashAlg, masterSecret, 's ap traffic', postSfHash));
    const cAppCipher = new Tls13RecordCipher(suite, deriveSecret(suite.hashAlg, masterSecret, 'c ap traffic', postSfHash));

    if (opts.coalescePlaintextFlightAfterSh) {
      // Attack: coalesce plaintext ServerHello || EncryptedExtensions || Certificate || CV || Finished in one 0x16 record!
      sock.write(wrapRec(TLS_CONTENT_HANDSHAKE, Buffer.concat([shMsg, eeMsg, certMsg, cvMsg, sfMsg])));
      return null;
    }

    sock.write(wrapRec(TLS_CONTENT_HANDSHAKE, shMsg));
    if (opts.ccsCount) {
      for (let i = 0; i < opts.ccsCount; i += 1) {
        sock.write(wrapRec(TLS_CONTENT_CHANGE_CIPHER_SPEC, Buffer.from([0x01])));
      }
    }
    sock.write(sHsCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, Buffer.concat([eeMsg, certMsg, cvMsg, sfMsg])));
    if (opts.stopBeforeClientFinished) return null;

    const cRec = await readRec();
    if (cRec.type === TLS_CONTENT_APPLICATION_DATA) {
      cHsCipher.decryptRecord(cRec.header, cRec.payload);
    }
    return { sAppCipher, cAppCipher };
  };

  try {
    // 1. Plaintext post-handshake CONTENT_ALERT (0x15 close_notify) truncation attack -> MUST fail with unexpected_message (10), NOT clean EOF!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec);
        sock.write(Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem });
        const err = await new Promise((resolve) => {
          duplex.on('data', () => {});
          duplex.once('end', () => resolve(new Error('INCORRECT_CLEAN_EOF')));
          duplex.once('error', (e) => resolve(e));
        });
        assert.ok(err instanceof TlsProtocolError, `expected TlsProtocolError, got ${err}`);
        assert.equal(err.alertDescription, 10);
      } finally {
        await srv.close();
      }
    }

    // 2. Post-handshake unencrypted ChangeCipherSpec (0x14) -> MUST fail with unexpected_message (10)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec);
        sock.write(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem });
        const err = await new Promise((resolve) => {
          duplex.on('data', () => {});
          duplex.once('error', (e) => resolve(e));
        });
        assert.ok(err instanceof TlsProtocolError);
        assert.equal(err.alertDescription, 10);
      } finally {
        await srv.close();
      }
    }

    // 3. Key-change boundary: plaintext flight coalesced after ServerHello -> MUST reject with unexpected_message (10)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, { coalescePlaintextFlightAfterSh: true });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        await assert.rejects(
          () => performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 10,
        );
      } finally {
        await srv.close();
      }
    }

    // 4. Key-change boundary: trailing handshake bytes coalesced after HRR -> MUST reject with unexpected_message (10)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, { sendHrr: true, hrrGroup: TLS_GROUP_SECP256R1, coalesceAfterHrr: true, stopAfterHrr: true });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        await assert.rejects(
          () => performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 10,
        );
      } finally {
        await srv.close();
      }
    }

    // 5. Key-change boundary: trailing handshake bytes coalesced after KeyUpdate in same record -> MUST reject with unexpected_message (10)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        const { sAppCipher } = await doServerHandshake(sock, readRec);
        const ku = wrapHs(TLS_HS_KEY_UPDATE, Buffer.from([0x00]));
        const trailingNst = wrapHs(TLS_HS_NEW_SESSION_TICKET, Buffer.alloc(16));
        sock.write(sAppCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, Buffer.concat([ku, trailingNst])));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem });
        const err = await new Promise((resolve) => {
          duplex.on('data', () => {});
          duplex.once('error', (e) => resolve(e));
        });
        assert.ok(err instanceof TlsProtocolError);
        assert.equal(err.alertDescription, 10);
      } finally {
        await srv.close();
      }
    }

    // 6. Empty post-HS Handshake fragment -> MUST reject with unexpected_message (10)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        const { sAppCipher } = await doServerHandshake(sock, readRec);
        sock.write(sAppCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, Buffer.alloc(0)));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem });
        const err = await new Promise((resolve) => {
          duplex.on('data', () => {});
          duplex.once('error', (e) => resolve(e));
        });
        assert.ok(err instanceof TlsProtocolError);
        assert.equal(err.alertDescription, 10);
      } finally {
        await srv.close();
      }
    }

    // 7. Interleaved ApplicationData AND Alert while partial post-HS handshake message buffered -> MUST reject with unexpected_message (10)!
    for (const interleaveType of [TLS_CONTENT_APPLICATION_DATA, TLS_CONTENT_ALERT]) {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        const { sAppCipher } = await doServerHandshake(sock, readRec);
        const fullNst = wrapHs(TLS_HS_NEW_SESSION_TICKET, Buffer.alloc(20));
        sock.write(sAppCipher.encryptRecord(TLS_CONTENT_HANDSHAKE, fullNst.subarray(0, 8)));
        const payload = interleaveType === TLS_CONTENT_ALERT ? Buffer.from([1, 0]) : Buffer.from('interleaved');
        sock.write(sAppCipher.encryptRecord(interleaveType, payload));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem });
        const err = await new Promise((resolve) => {
          duplex.on('data', () => {});
          duplex.once('error', (e) => resolve(e));
        });
        assert.ok(err instanceof TlsProtocolError);
        assert.equal(err.alertDescription, 10);
      } finally {
        await srv.close();
      }
    }

    // 8. Re-entrant destroy() inside 'data' callback MUST stop draining subsequent buffered records cleanly!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        const { sAppCipher } = await doServerHandshake(sock, readRec);
        const rec1 = sAppCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.from('first-chunk'));
        const rec2 = sAppCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.from('second-chunk-must-not-deliver'));
        sock.write(Buffer.concat([rec1, rec2]));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem });
        const received = [];
        await new Promise((resolve) => {
          duplex.on('data', (chunk) => {
            received.push(chunk.toString());
            duplex.destroy();
            resolve();
          });
        });
        await new Promise((r) => setTimeout(r, 30));
        assert.deepEqual(received, ['first-chunk']);
      } finally {
        await srv.close();
      }
    }

    // 9. HRR requests secp256r1, server illegally replies with CH1's X25519 in ServerHello -> MUST reject with illegal_parameter (47)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, {
          sendHrr: true,
          hrrGroup: TLS_GROUP_SECP256R1,
          shGroupOverride: TLS_GROUP_X25519,
          stopBeforeClientFinished: true,
        });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        await assert.rejects(
          () => performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 47,
        );
      } finally {
        await srv.close();
      }
    }

    // 10. HRR requests X25519 (already offered in CH1) even WITH cookie -> MUST reject with illegal_parameter (47)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, {
          sendHrr: true,
          hrrGroup: TLS_GROUP_X25519,
          hrrCookie: Buffer.from('cookie-123'),
          stopAfterHrr: true,
        });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        await assert.rejects(
          () => performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 47,
        );
      } finally {
        await srv.close();
      }
    }

    // 11. Unsolicited extensions: non-HRR ServerHello with EXT_ECH (0xFE0D) or EXT_COOKIE (0x002C) -> unsupported_extension (110)!
    for (const extraExt of [
      ext(TLS_EXT_ECH, Buffer.alloc(8)),
      ext(TLS_EXT_COOKIE, Buffer.concat([u16(4), Buffer.from('abcd')])),
    ]) {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, { shExtraExt: extraExt, stopBeforeClientFinished: true });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        await assert.rejects(
          () => performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 110,
        );
      } finally {
        await srv.close();
      }
    }

    // 12. HRR with unsolicited extension (ALPN 0x0010) -> unsupported_extension (110)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, {
          sendHrr: true,
          hrrGroup: TLS_GROUP_SECP256R1,
          hrrExtraExt: ext(TLS_EXT_ALPN, Buffer.from([0, 3, 2, 0x68, 0x32])),
          stopAfterHrr: true,
        });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        await assert.rejects(
          () => performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 110,
        );
      } finally {
        await srv.close();
      }
    }

    // 13. EncryptedExtensions with EXT_ALPN when client offered NO ALPN -> unsupported_extension (110)!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, { sendAlpn: true, stopBeforeClientFinished: true });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        await assert.rejects(
          () =>
            performTls13EchHandshake(socket, {
              realHost: 'secret.neruton.test',
              echConfigList,
              ca: pki.rootPem,
              alpn: [],
            }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 110,
        );
      } finally {
        await srv.close();
      }
    }

    // 14. TLS 1.3 record sequence overflow & padded TLSInnerPlaintext > 16385 rejection
    {
      const spec = getCipherSuiteSpec(TLS_AES_128_GCM_SHA256);
      const sec = crypto.randomBytes(spec.hashLen);
      const maxSeqCipher = new Tls13RecordCipher(spec, sec, (1n << 64n) - 1n);
      assert.throws(
        () => maxSeqCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.from('x')),
        (e) => e instanceof TlsProtocolError && /sequence number overflow/i.test(e.message),
      );

      // Padded TLSInnerPlaintext of 16386 bytes (16384 data + 1 type + 1 zero pad = 16386 > 16385) rejected!
      const enc = new Tls13RecordCipher(spec, sec);
      assert.throws(
        () => enc.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.alloc(TLS_MAX_PLAINTEXT), 1),
        (e) => e instanceof TlsProtocolError && e.alertDescription === 22,
      );
    }

    // 15. Backpressure EOF integrity: server writes 256 KiB (16 × 16 KiB records) + sock.end(); slow reader pulling every 15ms MUST receive ALL 262,144 bytes with ZERO truncation!
    {
      const payload = crypto.randomBytes(256 * 1024);
      const srv = await runAdversarialServer(async (sock, readRec) => {
        const { sAppCipher } = await doServerHandshake(sock, readRec);
        const recs = [];
        for (let off = 0; off < payload.length; off += TLS_MAX_PLAINTEXT) {
          recs.push(
            sAppCipher.encryptRecord(
              TLS_CONTENT_APPLICATION_DATA,
              payload.subarray(off, off + TLS_MAX_PLAINTEXT),
            ),
          );
        }
        sock.end(Buffer.concat(recs));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, {
          realHost: 'secret.neruton.test',
          echConfigList,
          ca: pki.rootPem,
        });
        const received = await new Promise((resolve, reject) => {
          const chunks = [];
          duplex.on('data', (c) => {
            chunks.push(Buffer.from(c));
            duplex.pause();
            setTimeout(() => {
              if (!duplex.destroyed) duplex.resume();
            }, 15);
          });
          duplex.once('end', () => resolve(Buffer.concat(chunks)));
          duplex.once('error', reject);
        });
        assert.equal(received.length, payload.length, 'backpressure slow-reader MUST NOT truncate buffered records on TCP FIN/close');
        assert.deepEqual(received, payload);
      } finally {
        await srv.close();
      }
    }

    // 16. Truncated TLS record at TCP EOF (100 bytes of a 500-byte ciphertext record left in rawBuf) -> MUST fail with TlsProtocolError (DECODE_ERROR 50), NOT clean EOF!
    {
      const srv = await runAdversarialServer(async (sock, readRec) => {
        const { sAppCipher } = await doServerHandshake(sock, readRec);
        const fullRec = sAppCipher.encryptRecord(TLS_CONTENT_APPLICATION_DATA, Buffer.alloc(480, 0xab));
        // Send only 100 bytes of the encrypted record and close TCP!
        sock.end(fullRec.subarray(0, 100));
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srv.port }]);
        const duplex = await performTls13EchHandshake(socket, {
          realHost: 'secret.neruton.test',
          echConfigList,
          ca: pki.rootPem,
        });
        const err = await new Promise((resolve) => {
          duplex.on('data', () => {});
          duplex.once('end', () => resolve(new Error('INCORRECT_CLEAN_EOF_ON_TRUNCATED_RECORD')));
          duplex.once('error', (e) => resolve(e));
        });
        assert.ok(err instanceof TlsProtocolError, `expected TlsProtocolError, got ${err}`);
        assert.equal(err.alertDescription, 50);
      } finally {
        await srv.close();
      }
    }

    // 17. Unbounded handshake ChangeCipherSpec flood DoS: 50 consecutive CCS records MUST fail with unexpected_message (10), while 2 CCS records succeed!
    {
      const srvFlood = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, { ccsCount: 50, stopBeforeClientFinished: true });
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srvFlood.port }]);
        await assert.rejects(
          () => performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem }),
          (e) => e instanceof TlsProtocolError && e.alertDescription === 10,
        );
      } finally {
        await srvFlood.close();
      }

      const srvOk = await runAdversarialServer(async (sock, readRec) => {
        await doServerHandshake(sock, readRec, { ccsCount: 2 });
        sock.end();
      });
      try {
        const { socket } = await connectTcpWithFailover([{ host: '127.0.0.1', port: srvOk.port }]);
        const duplex = await performTls13EchHandshake(socket, { realHost: 'secret.neruton.test', echConfigList, ca: pki.rootPem });
        assert.equal(duplex.echStatus, 'accepted');
        duplex.destroy();
      } finally {
        await srvOk.close();
      }
    }
  } finally {
    pki.cleanup();
  }
});
