import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import tls from 'node:tls';
import { WebSocketServer } from 'ws';
import {
  ClientHelloFragmentDuplex,
  ConfigError,
  DEFAULT_DOH_ENDPOINTS,
  DNS_TYPE_A,
  DNS_TYPE_AAAA,
  DNS_TYPE_CNAME,
  DNS_TYPE_HTTPS,
  DohError,
  NerutonError,
  SVC_PARAM_ALPN,
  SVC_PARAM_ECH,
  SVC_PARAM_IPV4HINT,
  SVC_PARAM_IPV6HINT,
  WsByteStream,
  YamuxSession,
  connect,
  connectTcpWithFailover,
  createStealthTlsSocket,
  decodeDnsResponse,
  encodeDnsQuery,
  findClientHelloSplitPoints,
  formatIpv6,
  loadConfig,
  parseConfigToml,
  parseDohOption,
  parseHttpsRdata,
  parseSniMode,
  planStealthTls,
  resolveConnectionSettings,
  resolveHostWithDoh,
  runCli,
  saveConfig,
  serializeConfigToml,
  shouldSkipDoh,
} from '../dist/esm/index.js';

function captureStream() {
  const s = new PassThrough();
  const chunks = [];
  s.on('data', (c) => chunks.push(Buffer.from(c)));
  return {
    stream: s,
    text: () => Buffer.concat(chunks).toString('utf8'),
  };
}

function generateSelfSignedCert(cn, sanEntries) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-tls-cert-'));
  const keyPath = path.join(dir, 'key.pem');
  const certPath = path.join(dir, 'cert.pem');
  try {
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-keyout',
        keyPath,
        '-out',
        certPath,
        '-days',
        '1',
        '-nodes',
        '-subj',
        `/CN=${cn}`,
        '-addext',
        `subjectAltName=${sanEntries.join(',')}`,
      ],
      { stdio: 'ignore' },
    );
    return {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function encodeDnsNameUncompressed(name) {
  const clean = name.replace(/\.+$/, '');
  if (!clean) return Buffer.from([0x00]);
  const parts = [];
  for (const label of clean.split('.')) {
    const b = Buffer.from(label, 'ascii');
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0x00]));
  return Buffer.concat(parts);
}

function buildDnsResponse(queryBuf, records, rcode = 0) {
  const id = queryBuf.readUInt16BE(0);
  // Copy question section starting at offset 12
  const question = queryBuf.subarray(12);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x8180 | (rcode & 0x0f), 2); // QR=1, RD=1, RA=1
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(records.length, 6); // ANCOUNT
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);

  const ansBufs = records.map((rec) => {
    // Use RFC 1035 compression pointer 0xc00c pointing back to QNAME at offset 12
    const namePtr = Buffer.from([0xc0, 0x0c]);
    const meta = Buffer.alloc(10);
    meta.writeUInt16BE(rec.type, 0);
    meta.writeUInt16BE(rec.rrClass ?? 1, 2); // IN by default
    meta.writeUInt32BE(rec.ttl ?? 300, 4);
    meta.writeUInt16BE(rec.rdata.length, 8);
    return Buffer.concat([namePtr, meta, rec.rdata]);
  });

  return Buffer.concat([header, question, ...ansBufs]);
}

function buildHttpsRdata({ priority = 1, targetName = '', alpn = [], ipv4Hints = [], ech, ipv6Hints = [] }) {
  const prioBuf = Buffer.alloc(2);
  prioBuf.writeUInt16BE(priority, 0);
  const targetBuf = encodeDnsNameUncompressed(targetName);
  const paramBufs = [];

  const pushParam = (key, val) => {
    const hdr = Buffer.alloc(4);
    hdr.writeUInt16BE(key, 0);
    hdr.writeUInt16BE(val.length, 2);
    paramBufs.push(hdr, val);
  };

  if (alpn.length > 0) {
    const parts = alpn.map((p) => {
      const b = Buffer.from(p, 'ascii');
      return Buffer.concat([Buffer.from([b.length]), b]);
    });
    pushParam(SVC_PARAM_ALPN, Buffer.concat(parts));
  }
  if (ipv4Hints.length > 0) {
    pushParam(
      SVC_PARAM_IPV4HINT,
      Buffer.concat(ipv4Hints.map((ip) => Buffer.from(ip.split('.').map(Number)))),
    );
  }
  if (ech) {
    pushParam(SVC_PARAM_ECH, Buffer.from(ech));
  }
  if (ipv6Hints.length > 0) {
    pushParam(SVC_PARAM_IPV6HINT, Buffer.concat(ipv6Hints));
  }

  return Buffer.concat([prioBuf, targetBuf, ...paramBufs]);
}

function parseQueryQtype(queryBuf) {
  let pos = 12;
  while (pos < queryBuf.length && queryBuf[pos] !== 0) {
    pos += 1 + queryBuf[pos];
  }
  pos += 1; // skip root 0x00
  return queryBuf.readUInt16BE(pos);
}

function startMockDohHttpsServer(certBundle, handler) {
  return new Promise((resolve) => {
    const server = https.createServer({ key: certBundle.key, cert: certBundle.cert }, (req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(Buffer.from(c)));
      req.on('end', () => {
        handler(req, res, Buffer.concat(chunks));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({
        server,
        port,
        url: `https://127.0.0.1:${port}/dns-query`,
        close: () =>
          new Promise((done) => {
            server.closeAllConnections?.();
            server.close(() => done());
          }),
      });
    });
  });
}

test('DNS wire codec encodes RFC 1035 queries and decodes A, AAAA, CNAME, and HTTPS/ECH records', () => {
  const qA = encodeDnsQuery('neruton.moer.eu.org', DNS_TYPE_A);
  assert.equal(qA.readUInt16BE(0), 0, 'RFC 8484 default query ID should be 0');
  assert.equal(qA.readUInt16BE(2), 0x0100, 'RD flag set');
  assert.equal(qA.readUInt16BE(4), 1, 'QDCOUNT = 1');
  assert.equal(parseQueryQtype(qA), DNS_TYPE_A);

  const ipv6Raw = Buffer.from([
    0x26, 0x06, 0x47, 0x00, 0x30, 0x32, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x68, 0x15, 0x02, 0xf7,
  ]);
  assert.equal(formatIpv6(ipv6Raw), '2606:4700:3032::6815:2f7');
  assert.equal(
    formatIpv6(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])),
    '::1',
  );

  const sampleEch = Buffer.from([0x00, 0x08, 0xfe, 0x0d, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);
  const httpsRdata = buildHttpsRdata({
    priority: 1,
    targetName: '',
    alpn: ['h2', 'http/1.1'],
    ipv4Hints: ['104.21.2.247', '172.67.129.230'],
    ech: sampleEch,
    ipv6Hints: [ipv6Raw],
  });

  const parsedSvc = parseHttpsRdata(httpsRdata);
  assert.equal(parsedSvc.priority, 1);
  assert.equal(parsedSvc.targetName, '');
  assert.deepEqual(parsedSvc.alpn, ['h2', 'http/1.1']);
  assert.deepEqual(parsedSvc.ipv4Hints, ['104.21.2.247', '172.67.129.230']);
  assert.deepEqual(parsedSvc.ipv6Hints, ['2606:4700:3032::6815:2f7']);
  assert.equal(parsedSvc.echConfigs.length, 1);
  assert.deepEqual(parsedSvc.echConfigs[0], sampleEch);

  const resp = buildDnsResponse(qA, [
    { type: DNS_TYPE_CNAME, rdata: encodeDnsNameUncompressed('edge.moer.eu.org') },
    { type: DNS_TYPE_A, rdata: Buffer.from([104, 21, 2, 247]) },
    { type: DNS_TYPE_AAAA, rdata: ipv6Raw },
    { type: DNS_TYPE_HTTPS, rdata: httpsRdata },
  ]);

  const decoded = decodeDnsResponse(resp);
  assert.equal(decoded.rcode, 0);
  assert.equal(decoded.answers.length, 4);
  assert.equal(decoded.answers[0].name, 'neruton.moer.eu.org');
  assert.equal(decoded.answers[0].cname, 'edge.moer.eu.org');
  assert.equal(decoded.answers[1].address, '104.21.2.247');
  assert.equal(decoded.answers[2].address, '2606:4700:3032::6815:2f7');
  assert.deepEqual(decoded.answers[3].https.echConfigs[0], sampleEch);

  // Compression pointer loop must throw DohError cleanly
  const loopBuf = Buffer.alloc(18);
  loopBuf.writeUInt16BE(0x8180, 2); // QR=1
  loopBuf.writeUInt16BE(1, 4); // QDCOUNT = 1
  loopBuf[12] = 0xc0;
  loopBuf[13] = 0x0c; // points to itself at offset 12
  assert.throws(() => decodeDnsResponse(loopBuf), (e) => e instanceof DohError);

  // Packet with QR=0 (query, not response) must be rejected
  assert.throws(
    () => decodeDnsResponse(qA),
    (e) => e instanceof DohError && e.code === 'DOH_MALFORMED_RESPONSE',
  );

  // Non-IN rrClass records must not be extracted as A/AAAA/HTTPS addresses
  const nonInResp = buildDnsResponse(qA, [
    { type: DNS_TYPE_A, rrClass: 3, rdata: Buffer.from([1, 2, 3, 4]) }, // CH class
    { type: DNS_TYPE_A, rrClass: 1, rdata: Buffer.from([104, 21, 2, 247]) }, // IN class
  ]);
  const nonInDecoded = decodeDnsResponse(nonInResp);
  assert.equal(nonInDecoded.answers[0].address, undefined);
  assert.equal(nonInDecoded.answers[1].address, '104.21.2.247');

  // Auto-skip rules
  assert.equal(shouldSkipDoh('127.0.0.1'), true);
  assert.equal(shouldSkipDoh('::1'), true);
  assert.equal(shouldSkipDoh('[::1]'), true);
  assert.equal(shouldSkipDoh('localhost'), true);
  assert.equal(shouldSkipDoh('api.localhost'), true);
  assert.equal(shouldSkipDoh('printer.local'), true);
  assert.equal(shouldSkipDoh('neruton.moer.eu.org'), false);
  assert.deepEqual(DEFAULT_DOH_ENDPOINTS, [
    'https://1.0.0.1/dns-query',
    'https://223.5.5.5/dns-query',
    'https://1.1.1.1/dns-query',
    'https://8.8.4.4/dns-query',
  ]);
});

test('Mock DoH server: parallel A/AAAA/HTTPS POST, racing first two, fallback wave, strict fail, auto fallback', async () => {
  const dohCert = generateSelfSignedCert('127.0.0.1', ['IP:127.0.0.1']);
  const seenQtypes = new Set();
  const sampleEch = Buffer.from([0x00, 0x06, 0xfe, 0x0d, 0x11, 0x22, 0x33, 0x44]);

  const goodDoh = await startMockDohHttpsServer(dohCert, (req, res, body) => {
    assert.equal(req.method, 'POST');
    assert.equal(req.headers['content-type'], 'application/dns-message');
    assert.equal(req.headers.accept, 'application/dns-message');
    const qtype = parseQueryQtype(body);
    seenQtypes.add(qtype);

    let records = [];
    if (qtype === DNS_TYPE_A) {
      records = [{ type: DNS_TYPE_A, rdata: Buffer.from([127, 0, 0, 1]) }];
    } else if (qtype === DNS_TYPE_AAAA) {
      records = [
        {
          type: DNS_TYPE_AAAA,
          rdata: Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
        },
      ];
    } else if (qtype === DNS_TYPE_HTTPS) {
      records = [
        {
          type: DNS_TYPE_HTTPS,
          rdata: buildHttpsRdata({ priority: 1, alpn: ['h2'], ech: sampleEch }),
        },
      ];
    }
    const wire = buildDnsResponse(body, records);
    res.writeHead(200, { 'Content-Type': 'application/dns-message' });
    res.end(wire);
  });

  const slowTimers = [];
  const slowDoh = await startMockDohHttpsServer(dohCert, (_req, res) => {
    const t = setTimeout(() => {
      if (!res.writableEnded) {
        res.writeHead(504);
        res.end();
      }
    }, 5000);
    t.unref();
    slowTimers.push(t);
  });

  const failingDoh = await startMockDohHttpsServer(dohCert, (_req, res) => {
    res.writeHead(502);
    res.end('bad gateway');
  });

  try {
    // 1. Race slow endpoint #1 against fast endpoint #2 — must finish fast from #2!
    const t0 = Date.now();
    const raced = await resolveHostWithDoh('app.example.test', {
      doh: [slowDoh.url, goodDoh.url],
      timeoutMs: 2500,
      ca: dohCert.cert,
    });
    const elapsed = Date.now() - t0;
    assert.ok(elapsed < 1500, `expected race winner quickly, took ${elapsed}ms`);
    assert.equal(raced.source, 'doh');
    assert.equal(raced.endpoint, goodDoh.url);
    assert.deepEqual(raced.ipv4, ['127.0.0.1']);
    assert.deepEqual(raced.ipv6, ['::1']);
    assert.deepEqual(raced.addresses, ['127.0.0.1', '::1']);
    assert.equal(raced.echConfigs.length, 1);
    assert.deepEqual(raced.echConfigs[0], sampleEch);
    assert.ok(seenQtypes.has(DNS_TYPE_A));
    assert.ok(seenQtypes.has(DNS_TYPE_AAAA));
    assert.ok(seenQtypes.has(DNS_TYPE_HTTPS));

    // 2. Fallback wave: first two endpoints fail, 3rd succeeds
    const fallbackWave = await resolveHostWithDoh('app.example.test', {
      doh: [failingDoh.url, failingDoh.url, goodDoh.url],
      timeoutMs: 1500,
      ca: dohCert.cert,
    });
    assert.equal(fallbackWave.source, 'doh');
    assert.equal(fallbackWave.endpoint, goodDoh.url);

    // 3. Explicit custom DoH URL fails closed (strict) rather than silently falling back to plaintext DNS
    await assert.rejects(
      () =>
        resolveHostWithDoh('app.example.test', {
          doh: [failingDoh.url],
          timeoutMs: 1500,
          ca: dohCert.cert,
        }),
      (err) => err instanceof DohError && err.code === 'DOH_FAILED',
    );

    // 4. Auto mode warns and falls back to system DNS when all endpoints fail
    const warnings = [];
    const autoFallback = await resolveHostWithDoh('app.example.test', {
      doh: { mode: 'auto', endpoints: [failingDoh.url], isCustom: false },
      timeoutMs: 1500,
      ca: dohCert.cert,
      onWarn: (w) => warnings.push(w),
    });
    assert.equal(autoFallback.source, 'fallback');
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /falling back to system DNS/);

    // 5. Off mode skips DoH completely
    const offRes = await resolveHostWithDoh('app.example.test', { doh: false });
    assert.equal(offRes.source, 'off');
  } finally {
    for (const t of slowTimers) clearTimeout(t);
    await Promise.all([goodDoh.close(), slowDoh.close(), failingDoh.close()]);
  }
});

test('Regression: fast NXDOMAIN/empty DoH response does not win race, HTTPS priority sorting works, and auto falls back', async () => {
  const dohCert = generateSelfSignedCert('127.0.0.1', ['IP:127.0.0.1']);
  const echPrio1 = Buffer.from([0x00, 0x04, 0xfe, 0x0d, 0xaa, 0xaa]);
  const echPrio2 = Buffer.from([0x00, 0x04, 0xfe, 0x0d, 0xbb, 0xbb]);

  const nxdomainDoh = await startMockDohHttpsServer(dohCert, (_req, res, body) => {
    res.writeHead(200, { 'Content-Type': 'application/dns-message' });
    res.end(buildDnsResponse(body, [], 3)); // fast NXDOMAIN (0 answers)
  });

  const slowerWorkingDoh = await startMockDohHttpsServer(dohCert, (_req, res, body) => {
    const qtype = parseQueryQtype(body);
    setTimeout(() => {
      let records = [];
      if (qtype === DNS_TYPE_A) {
        records = [{ type: DNS_TYPE_A, rdata: Buffer.from([198, 51, 100, 9]) }];
      } else if (qtype === DNS_TYPE_HTTPS) {
        // Deliberately return priority 2 BEFORE priority 1 to verify ascending priority sort
        records = [
          { type: DNS_TYPE_HTTPS, rdata: buildHttpsRdata({ priority: 2, ech: echPrio2 }) },
          { type: DNS_TYPE_HTTPS, rdata: buildHttpsRdata({ priority: 1, ech: echPrio1 }) },
        ];
      }
      res.writeHead(200, { 'Content-Type': 'application/dns-message' });
      res.end(buildDnsResponse(body, records, 0));
    }, 60);
  });

  try {
    // Racing fast NXDOMAIN against slower working endpoint must NOT abort the working endpoint!
    const res = await resolveHostWithDoh('race.example.test', {
      doh: [nxdomainDoh.url, slowerWorkingDoh.url],
      timeoutMs: 2500,
      ca: dohCert.cert,
    });
    assert.equal(res.source, 'doh');
    assert.equal(res.endpoint, slowerWorkingDoh.url);
    assert.deepEqual(res.addresses, ['198.51.100.9']);
    assert.equal(res.httpsRecords.length, 2);
    assert.equal(res.httpsRecords[0].priority, 1);
    assert.equal(res.httpsRecords[1].priority, 2);
    assert.deepEqual(res.echConfigs[0], echPrio1);
    assert.deepEqual(res.echConfigs[1], echPrio2);

    // When all endpoints return NXDOMAIN/empty: strict fails, auto warns and falls back to system DNS
    await assert.rejects(
      () =>
        resolveHostWithDoh('missing.example.test', {
          doh: [nxdomainDoh.url],
          timeoutMs: 1500,
          ca: dohCert.cert,
        }),
      (err) => err instanceof DohError && err.code === 'DOH_FAILED',
    );

    const warns = [];
    const fb = await resolveHostWithDoh('missing.example.test', {
      doh: { mode: 'auto', endpoints: [nxdomainDoh.url], isCustom: false },
      timeoutMs: 1500,
      ca: dohCert.cert,
      onWarn: (w) => warns.push(w),
    });
    assert.equal(fb.source, 'fallback');
    assert.equal(warns.length, 1);
  } finally {
    await Promise.all([nxdomainDoh.close(), slowerWorkingDoh.close()]);
  }
});

test('Regression: ClientHelloFragmentDuplex.destroy(err) does not trigger uncaught error on raw net.Socket', async () => {
  const srv = net.createServer((s) => {
    s.on('error', () => {});
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;

  let uncaught = null;
  const onUncaught = (err) => {
    uncaught = err;
  };
  process.on('uncaughtException', onUncaught);

  try {
    const raw = net.connect(port, '127.0.0.1');
    await new Promise((r) => raw.once('connect', r));
    const duplex = new ClientHelloFragmentDuplex(raw);
    let duplexErr = null;
    duplex.on('error', (err) => {
      duplexErr = err;
    });
    duplex.destroy(new Error('CERT_CHECK_FAILED'));
    await new Promise((r) => setTimeout(r, 40));

    assert.equal(uncaught, null, `unexpected uncaughtException: ${uncaught}`);
    assert.equal(duplexErr?.message, 'CERT_CHECK_FAILED');
    assert.equal(raw.destroyed, true);
  } finally {
    process.off('uncaughtException', onUncaught);
    await new Promise((r) => srv.close(r));
  }
});

test('ClientHello Duplex fragmentation splits ClientHello across multiple TCP segments on wire and completes TLS 1.3', async () => {
  const targetHost = 'stealth.neruton.test';
  const serverCert = generateSelfSignedCert(targetHost, [`DNS:${targetHost}`, 'IP:127.0.0.1']);

  // Local TLS server listening on loopback
  let serverSeenSni = null;
  const tlsServer = tls.createServer(
    {
      key: serverCert.key,
      cert: serverCert.cert,
      SNICallback: (servername, cb) => {
        serverSeenSni = servername;
        cb(null, null);
      },
    },
    (sock) => {
      sock.on('data', (chunk) => {
        sock.write(chunk); // echo back over TLS
      });
    },
  );
  await new Promise((r) => tlsServer.listen(0, '127.0.0.1', r));
  const tlsPort = tlsServer.address().port;

  // Raw TCP wire observer proxy in front of tlsServer to inspect actual TCP segments arriving on wire!
  const wireSegments = [];
  let clientHelloComplete = false;
  let capturedBytes = 0;
  let expectedRecordTotal = Infinity;

  const tcpObserver = net.createServer((downstream) => {
    downstream.setNoDelay(true);
    const upstream = net.connect(tlsPort, '127.0.0.1');
    upstream.setNoDelay(true);
    downstream.on('data', (chunk) => {
      if (!clientHelloComplete) {
        wireSegments.push(Buffer.from(chunk));
        capturedBytes += chunk.length;
        const combined = Buffer.concat(wireSegments);
        if (combined.length >= 5 && combined[0] === 0x16 && combined[1] === 0x03) {
          expectedRecordTotal = 5 + combined.readUInt16BE(3);
        }
        if (capturedBytes >= expectedRecordTotal) {
          clientHelloComplete = true;
        }
      }
      upstream.write(chunk);
    });
    upstream.on('data', (chunk) => downstream.write(chunk));
    downstream.on('end', () => upstream.end());
    upstream.on('end', () => downstream.end());
    downstream.on('error', () => upstream.destroy());
    upstream.on('error', () => downstream.destroy());
  });
  await new Promise((r) => tcpObserver.listen(0, '127.0.0.1', r));
  const observerPort = tcpObserver.address().port;

  try {
    const plan = planStealthTls({
      wsUrl: new URL(`wss://${targetHost}:${observerPort}/_neruton/tunnel`),
      sniMode: 'fragment',
    });
    assert.equal(plan.fragmentClientHello, true);
    assert.equal(plan.servername, targetHost);

    const { socket: rawSock } = await connectTcpWithFailover([
      { host: '127.0.0.1', port: observerPort },
    ]);
    const { socket: tlsSock, duplex } = createStealthTlsSocket(rawSock, plan, {
      ca: serverCert.cert,
      fragmentOptions: { interFragmentDelayMs: 5 },
    });

    await new Promise((resolve, reject) => {
      tlsSock.once('secureConnect', resolve);
      tlsSock.once('error', reject);
    });

    assert.equal(tlsSock.authorized, true);
    assert.equal(tlsSock.getProtocol(), 'TLSv1.3');
    assert.equal(serverSeenSni, targetHost);
    assert.equal(duplex.didFragment, true);
    assert.ok(duplex.fragmentCount >= 3, `expected >=3 fragments, got ${duplex.fragmentCount}`);

    // Verify actual TCP segments received on the wire!
    assert.ok(
      wireSegments.length >= 2,
      `expected multiple TCP segments received on wire, got ${wireSegments.length} (${wireSegments.map((b) => b.length)})`,
    );
    assert.equal(wireSegments[0][0], 0x16);
    assert.equal(wireSegments[0][1], 0x03);
    assert.equal(wireSegments[0].length, 5, 'first wire segment must be the 5-byte TLS record header');
    for (const seg of wireSegments) {
      assert.equal(
        seg.includes(Buffer.from(targetHost, 'ascii')),
        false,
        `no single ClientHello wire segment should contain full SNI '${targetHost}'`,
      );
    }

    // Verify transparent pass-through works cleanly with large payload (backpressure exercise)
    const payload = Buffer.alloc(64 * 1024, 0x5a);
    const echoed = await new Promise((resolve, reject) => {
      const received = [];
      let total = 0;
      tlsSock.on('data', (c) => {
        received.push(c);
        total += c.length;
        if (total >= payload.length) {
          resolve(Buffer.concat(received));
        }
      });
      tlsSock.once('error', reject);
      tlsSock.write(payload);
    });
    assert.deepEqual(echoed, payload);

    // Verify clean teardown destroys underlying raw socket
    tlsSock.destroy();
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(rawSock.destroyed, true);
  } finally {
    await new Promise((r) => tcpObserver.close(r));
    await new Promise((r) => tlsServer.close(r));
  }
});

test('Omitted SNI (none), Custom SNI (--sni), strict checkServerIdentity, DoH + fragmentation end-to-end tunnel', async () => {
  const realHost = 'gw.neruton.test';
  const customSniHost = 'front.other.test';
  const goodCert = generateSelfSignedCert(realHost, [`DNS:${realHost}`]);
  const wrongCert = generateSelfSignedCert(customSniHost, [`DNS:${customSniHost}`]);
  const dohCert = generateSelfSignedCert('127.0.0.1', ['IP:127.0.0.1']);

  let lastSeenSni = 'UNSET';
  let activeCert = goodCert;

  const httpsGateway = https.createServer({
    key: goodCert.key,
    cert: goodCert.cert,
    SNICallback: (sn, cb) => {
      lastSeenSni = sn;
      cb(null, tls.createSecureContext({ key: activeCert.key, cert: activeCert.cert }));
    },
  });
  const wss = new WebSocketServer({ noServer: true });
  httpsGateway.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => {
      ws.once('message', () => {
        ws.send(
          JSON.stringify({
            ok: true,
            tunnel_id: 'tid-stealth',
            prefix: 'stealth-demo',
            public_url: `https://stealth-demo.${realHost}`,
            path_url: `https://${realHost}/t/stealth-demo/`,
            preview_url: `https://${realHost}/preview/stealth-demo`,
            dashboard_url: `https://${realHost}`,
            error: null,
          }),
        );
        const wsStream = new WsByteStream(ws);
        new YamuxSession(wsStream, { mode: 'client' });
      });
    });
  });
  await new Promise((r) => httpsGateway.listen(0, '127.0.0.1', r));
  const gwPort = httpsGateway.address().port;

  // Mock DoH server resolving realHost -> 127.0.0.1
  const dohServer = await startMockDohHttpsServer(dohCert, (_req, res, body) => {
    const qtype = parseQueryQtype(body);
    const records =
      qtype === DNS_TYPE_A ? [{ type: DNS_TYPE_A, rdata: Buffer.from([127, 0, 0, 1]) }] : [];
    res.writeHead(200, { 'Content-Type': 'application/dns-message' });
    res.end(buildDnsResponse(body, records));
  });

  const combinedCa = [goodCert.cert, wrongCert.cert, dohCert.cert];

  try {
    // 1. Default auto mode: DoH + ClientHello fragmentation against realHost
    lastSeenSni = 'UNSET';
    activeCert = goodCert;
    const tAuto = await connect({
      url: 3000,
      server: `https://${realHost}:${gwPort}`,
      doh: dohServer.url,
      ca: combinedCa,
      keepaliveIntervalMs: 0,
    });
    assert.equal(lastSeenSni, realHost);
    assert.equal(tAuto.transportInfo.dohSource, 'doh');
    assert.equal(tAuto.transportInfo.resolvedIp, '127.0.0.1');
    assert.equal(tAuto.transportInfo.effectiveSniMode, 'fragment');
    assert.equal(tAuto.transportInfo.fragmented, true);
    assert.ok(tAuto.transportInfo.fragmentCount >= 3);
    assert.equal(tAuto.transportInfo.tlsAuthorized, true);
    assert.match(tAuto.transportInfo.summary, /DoH/);
    assert.match(tAuto.transportInfo.summary, /ClientHello fragmentation/);
    await tAuto.close();

    // 2. Omitted SNI (sniMode: 'none') with matching realHost cert -> succeeds, no SNI sent
    lastSeenSni = 'UNSET';
    activeCert = goodCert;
    const tNone = await connect({
      url: 3000,
      server: `https://${realHost}:${gwPort}`,
      doh: dohServer.url,
      sniMode: 'none',
      ca: combinedCa,
      keepaliveIntervalMs: 0,
    });
    assert.equal(lastSeenSni, 'UNSET', 'SNI callback must not fire when SNI is omitted');
    assert.equal(tNone.transportInfo.effectiveSniMode, 'none');
    assert.equal(tNone.transportInfo.fragmented, false);
    assert.equal(tNone.transportInfo.tlsAuthorized, true);
    await tNone.close();

    // 2b. Omitted SNI (sniMode: 'none') with WRONG default server cert -> MUST REJECT strictly against realHost!
    httpsGateway.setSecureContext({ key: wrongCert.key, cert: wrongCert.cert });
    activeCert = wrongCert;
    await assert.rejects(
      () =>
        connect({
          url: 3000,
          server: `https://${realHost}:${gwPort}`,
          doh: dohServer.url,
          sniMode: 'none',
          ca: combinedCa,
          keepaliveIntervalMs: 0,
        }),
      /Hostname\/IP does not match|altnames|connect failed/i,
    );
    httpsGateway.setSecureContext({ key: goodCert.key, cert: goodCert.cert });

    // 3. Custom SNI (--sni) with sniMode: 'auto' -> sends custom SNI + fragments + validates cert against REAL host!
    lastSeenSni = 'UNSET';
    activeCert = goodCert;
    const tCustom = await connect({
      url: 3000,
      server: `https://${realHost}:${gwPort}`,
      doh: dohServer.url,
      sniMode: 'auto',
      sni: customSniHost,
      ca: combinedCa,
      keepaliveIntervalMs: 0,
    });
    assert.equal(lastSeenSni, customSniHost);
    assert.equal(tCustom.transportInfo.effectiveSniMode, 'fragment');
    assert.equal(tCustom.transportInfo.sni, customSniHost);
    assert.equal(tCustom.transportInfo.fragmented, true);
    assert.equal(tCustom.transportInfo.tlsAuthorized, true);
    await tCustom.close();

    // 4. Custom SNI when server returns cert for customSniHost (NOT realHost) -> MUST REJECT strictly!
    activeCert = wrongCert;
    await assert.rejects(
      () =>
        connect({
          url: 3000,
          server: `https://${realHost}:${gwPort}`,
          doh: dohServer.url,
          sniMode: 'auto',
          sni: customSniHost,
          ca: combinedCa,
          keepaliveIntervalMs: 0,
        }),
      /Hostname\/IP does not match|altnames|connect failed/i,
    );

    // 5. Same wrong cert succeeds only if noTlsVerify: true
    const tInsecure = await connect({
      url: 3000,
      server: `https://${realHost}:${gwPort}`,
      doh: dohServer.url,
      sniMode: 'auto',
      sni: customSniHost,
      noTlsVerify: true,
      ca: combinedCa,
      keepaliveIntervalMs: 0,
    });
    assert.equal(tInsecure.connected, true);
    await tInsecure.close();
  } finally {
    for (const c of wss.clients) c.terminate();
    await new Promise((r) => wss.close(r));
    await new Promise((r) => {
      httpsGateway.closeAllConnections?.();
      httpsGateway.close(r);
    });
    await dohServer.close();
  }
});

test('sniMode: ech fails fast with ECH_REQUIRED when no ECHConfigList is available (SDK and CLI) and never retries', async () => {
  let reconnectCalls = 0;
  await assert.rejects(
    () =>
      connect({
        url: 3000,
        server: 'https://127.0.0.1:1',
        sniMode: 'ech',
        retryInitialConnect: true,
        onReconnecting: () => {
          reconnectCalls += 1;
        },
      }),
    (err) => {
      assert.ok(err instanceof NerutonError);
      assert.equal(err.code, 'ECH_REQUIRED');
      assert.match(err.message, /ECHConfigList/);
      return true;
    },
  );
  assert.equal(reconnectCalls, 0, 'ECH_REQUIRED must fail fast without retrying');

  const stderr = captureStream();
  const code = await runCli(
    ['tunnel', '--url', '3000', '--server', 'https://127.0.0.1:1', '--sni-mode', 'ech'],
    { stderr: stderr.stream, env: {} },
  );
  assert.equal(code, 1);
  assert.match(stderr.text(), /ECHConfigList/);
});

test('Config TOML, env vars, CLI flags precedence & validation for doh/sni_mode/sni/ech_config', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-stealth-cfg-'));
  const cfgFile = path.join(tmpDir, 'config.toml');

  try {
    // Save string-only TOML keys matching Rust/Python schema
    saveConfig(
      {
        server: 'https://gw.example.com',
        token: 'ntk_tok',
        doh: 'strict',
        sniMode: 'fragment',
        sni: 'cfg.example.com',
        echConfig: 'AQIDBA==',
      },
      cfgFile,
    );

    const raw = fs.readFileSync(cfgFile, 'utf8');
    assert.match(raw, /doh = "strict"/);
    assert.match(raw, /sni_mode = "fragment"/);
    assert.match(raw, /sni = "cfg\.example\.com"/);
    assert.match(raw, /ech_config = "AQIDBA=="/);

    const loaded = loadConfig(cfgFile);
    assert.deepEqual(loaded, {
      server: 'https://gw.example.com',
      token: 'ntk_tok',
      doh: 'strict',
      sniMode: 'fragment',
      sni: 'cfg.example.com',
      echConfig: 'AQIDBA==',
    });
    assert.deepEqual(parseConfigToml(serializeConfigToml(loaded)), loaded);

    // Precedence level 1: config.toml
    const fromFile = resolveConnectionSettings({ configPath: cfgFile, env: {} });
    assert.equal(fromFile.doh.mode, 'strict');
    assert.equal(fromFile.sniMode, 'fragment');
    assert.equal(fromFile.sni, 'cfg.example.com');
    assert.equal(fromFile.echConfig, 'AQIDBA==');

    // Precedence level 2: env vars override config.toml
    const fromEnv = resolveConnectionSettings({
      configPath: cfgFile,
      env: {
        NERUTON_DOH: 'https://1.0.0.1/dns-query,https://8.8.4.4/dns-query',
        NERUTON_SNI_MODE: 'none',
        NERUTON_SNI: 'env.example.com',
        NERUTON_ECH_CONFIG: 'BQYH',
      },
    });
    assert.equal(fromEnv.doh.mode, 'strict');
    assert.equal(fromEnv.doh.isCustom, true);
    assert.deepEqual(fromEnv.doh.endpoints, [
      'https://1.0.0.1/dns-query',
      'https://8.8.4.4/dns-query',
    ]);
    assert.equal(fromEnv.sniMode, 'none');
    assert.equal(fromEnv.sni, 'env.example.com');
    assert.equal(fromEnv.echConfig, 'BQYH');

    // Precedence level 3: explicit options override env & config.toml (including doh: false!)
    const fromExplicit = resolveConnectionSettings({
      configPath: cfgFile,
      doh: false,
      sniMode: 'plain',
      sni: 'explicit.example.com',
      echConfig: 'CAkK',
      env: {
        NERUTON_DOH: 'strict',
        NERUTON_SNI_MODE: 'none',
        NERUTON_SNI: 'env.example.com',
        NERUTON_ECH_CONFIG: 'BQYH',
      },
    });
    assert.equal(fromExplicit.doh.mode, 'off');
    assert.equal(fromExplicit.sniMode, 'plain');
    assert.equal(fromExplicit.sni, 'explicit.example.com');
    assert.equal(fromExplicit.echConfig, 'CAkK');

    // Defaults when neither config nor env is set
    const defaults = resolveConnectionSettings({
      configPath: path.join(tmpDir, 'nonexistent.toml'),
      env: {},
    });
    assert.equal(defaults.doh.mode, 'auto');
    assert.equal(defaults.sniMode, 'auto');
    assert.equal(defaults.sni, undefined);
    assert.equal(defaults.echConfig, undefined);

    // Invalid option values throw ConfigError (including remote cleartext http:// DoH URLs)
    assert.throws(() => parseDohOption('bogus'), (e) => e instanceof ConfigError);
    assert.throws(() => parseDohOption('ftp://1.0.0.1/dns-query'), (e) => e instanceof ConfigError);
    assert.throws(() => parseDohOption('http://1.0.0.1/dns-query'), (e) => e instanceof ConfigError);
    assert.throws(() => parseDohOption('http://dns.example.com/dns-query'), (e) => e instanceof ConfigError);
    // Loopback http:// is permitted for local mocks/proxies
    assert.equal(parseDohOption('http://127.0.0.1:8080/dns-query').mode, 'strict');
    assert.equal(parseDohOption('http://[::1]:8080/dns-query').mode, 'strict');
    assert.equal(parseDohOption('http://localhost:8080/dns-query').mode, 'strict');
    assert.throws(() => parseSniMode('bogus'), (e) => e instanceof ConfigError);

    // CLI config set & show
    const outSet = captureStream();
    assert.equal(
      await runCli(
        [
          'config',
          'set',
          '--config',
          cfgFile,
          '--doh',
          'https://1.0.0.1/dns-query',
          '--sni-mode',
          'fragment',
          '--sni',
          'cli.example.com',
          '--ech-config',
          'TESTECH',
        ],
        { stdout: outSet.stream },
      ),
      0,
    );
    const outShow = captureStream();
    assert.equal(
      await runCli(['config', 'show', '--config', cfgFile], { stdout: outShow.stream, env: {} }),
      0,
    );
    const showTxt = outShow.text();
    assert.match(showTxt, /Effective DoH:\s+https:\/\/1\.0\.0\.1\/dns-query/);
    assert.match(showTxt, /Effective SNI:\s+mode=fragment, host=cli\.example\.com/);
    assert.match(showTxt, /Saved ECH config:\s+<configured>/);

    // CLI --no-doh saves doh = "off"
    assert.equal(
      await runCli(['config', 'set', '--config', cfgFile, '--no-doh'], {
        stdout: captureStream().stream,
      }),
      0,
    );
    assert.equal(loadConfig(cfgFile).doh, 'off');

    // CLI conflicting --doh and --no-doh fails cleanly
    const errConflict = captureStream();
    assert.equal(
      await runCli(['tunnel', '--url', '3000', '--doh', 'strict', '--no-doh'], {
        stderr: errConflict.stream,
      }),
      1,
    );
    assert.match(errConflict.text(), /cannot combine --doh and --no-doh/);

    // Pure split-point helper check
    const syntheticCh = Buffer.alloc(120, 0xaa);
    syntheticCh[0] = 0x16;
    syntheticCh[1] = 0x03;
    syntheticCh[2] = 0x01;
    syntheticCh.writeUInt16BE(115, 3);
    const cuts = findClientHelloSplitPoints(syntheticCh);
    assert.ok(cuts.length >= 2 && cuts[0] === 5);

    // Auto-skip SNI hiding on ws:// and localhost/IP unless explicitly requested
    assert.equal(
      planStealthTls({ wsUrl: new URL('ws://neruton.moer.eu.org/_neruton/tunnel') }).effectiveSniMode,
      'n/a',
    );
    assert.equal(
      planStealthTls({ wsUrl: new URL('wss://localhost:8443/_neruton/tunnel') }).fragmentClientHello,
      false,
    );
    assert.equal(
      planStealthTls({ wsUrl: new URL('wss://127.0.0.1:8443/_neruton/tunnel') }).fragmentClientHello,
      false,
    );
    assert.equal(
      planStealthTls({ wsUrl: new URL('wss://127.0.0.1:8443/_neruton/tunnel'), sniMode: 'fragment' })
        .fragmentClientHello,
      true,
    );
    assert.equal(
      planStealthTls({ wsUrl: new URL('wss://neruton.moer.eu.org/_neruton/tunnel') })
        .fragmentClientHello,
      true,
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Multi-IP TCP failover skips closed port and connects to working address', async () => {
  // Bind and immediately close a port to get a guaranteed refused port
  const closedSrv = net.createServer();
  await new Promise((r) => closedSrv.listen(0, '127.0.0.1', r));
  const deadPort = closedSrv.address().port;
  await new Promise((r) => closedSrv.close(r));

  const liveSrv = net.createServer((s) => {
    s.on('error', () => {});
    s.end('ok');
  });
  await new Promise((r) => liveSrv.listen(0, '127.0.0.1', r));
  const livePort = liveSrv.address().port;

  try {
    const res = await connectTcpWithFailover([
      { host: '127.0.0.1', port: deadPort },
      { host: '127.0.0.1', port: livePort },
    ]);
    res.socket.on('error', () => {});
    assert.equal(res.socket.remotePort, livePort);
    res.socket.destroy();
  } finally {
    await new Promise((r) => liveSrv.close(r));
  }
});
