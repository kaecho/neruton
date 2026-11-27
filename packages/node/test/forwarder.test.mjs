import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import { Duplex } from 'node:stream';
import WebSocket, { WebSocketServer } from 'ws';
import {
  LocalForwarder,
  YamuxFlag,
  YamuxFrameDecoder,
  YamuxFrameType,
  YamuxSession,
  createTargetConfig,
  normalizeTargetUrl,
} from '../dist/esm/index.js';

function createDuplexPair() {
  let peerA;
  let peerB;
  peerA = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      if (peerB.destroyed) {
        cb(new Error('closed'));
        return;
      }
      peerB.push(Buffer.from(chunk));
      cb();
    },
    final(cb) {
      peerB.push(null);
      cb();
    },
  });
  peerB = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      if (peerA.destroyed) {
        cb(new Error('closed'));
        return;
      }
      peerA.push(Buffer.from(chunk));
      cb();
    },
    final(cb) {
      peerA.push(null);
      cb();
    },
  });
  return [peerA, peerB];
}

function sendHttpOverYamux(clientSession, options, body) {
  return new Promise((resolve, reject) => {
    const stream = clientSession.openStream();
    stream.remoteAddress = '127.0.0.1';
    stream.setTimeout = () => stream;
    stream.setNoDelay = () => stream;
    stream.setKeepAlive = () => stream;
    stream.destroySoon = () => stream.end();

    const customAgent = new http.Agent({ keepAlive: false });
    customAgent.createConnection = () => stream;

    const req = http.request({
      ...options,
      agent: customAgent,
    });

    req.on('response', (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks),
        });
      });
    });
    req.on('error', reject);
    if (body) {
      req.write(body);
    }
    req.end();
  });
}

test('LocalForwarder proxies HTTP/1.1, Host modes, basePath, streaming chunks, and WS upgrades over Yamux', async () => {
  const backend = http.createServer((req, res) => {
    if (req.url?.startsWith('/inspect')) {
      res.writeHead(200, {
        'content-type': 'application/json',
        'set-cookie': ['a=1; Path=/', 'b=2; HttpOnly'],
      });
      res.end(JSON.stringify({ url: req.url, host: req.headers.host, method: req.method }));
      return;
    }
    if (req.url === '/stream') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.write('part-1|');
      setTimeout(() => {
        res.write('part-2|');
        setTimeout(() => {
          res.end('part-3');
        }, 15);
      }, 15);
      return;
    }
    if (req.url === '/echo') {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'application/octet-stream' });
        res.end(Buffer.concat(chunks));
      });
      return;
    }
    if (req.url === '/ws-reject') {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('ws forbidden');
      return;
    }
    res.writeHead(404);
    res.end('not found');
  });

  const wss = new WebSocketServer({ noServer: true });
  backend.on('upgrade', (req, socket, head) => {
    if (req.url === '/ws') {
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.on('message', (msg, isBinary) => {
          if (isBinary) {
            ws.send(Buffer.concat([Buffer.from('bin:'), msg]), { binary: true });
          } else {
            ws.send(`ws-echo:${msg.toString()}`);
          }
        });
      });
    } else if (req.url === '/ws-reject') {
      socket.write('HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 12\r\nConnection: close\r\n\r\nws forbidden');
      socket.end();
    } else {
      socket.destroy();
    }
  });

  await new Promise((r) => backend.listen(0, '127.0.0.1', r));
  const backendPort = backend.address().port;

  const [a, b] = createDuplexPair();
  const clientSession = new YamuxSession(a, { mode: 'client' });
  const serverSession = new YamuxSession(b, { mode: 'server' });

  const events = [];
  const targetCfg = createTargetConfig(normalizeTargetUrl(`http://127.0.0.1:${backendPort}`), {
    hostHeader: 'rewrite',
  });
  const forwarder = new LocalForwarder(targetCfg, (ev) => events.push(ev));
  serverSession.on('stream', (stream) => forwarder.handleStream(stream));

  try {
    // 1. Default Host rewriting + multi-value Set-Cookie
    const r1 = await sendHttpOverYamux(clientSession, {
      method: 'GET',
      path: '/inspect?x=1',
      headers: { host: 'public.moer.eu.org' },
    });
    assert.equal(r1.statusCode, 200);
    const j1 = JSON.parse(r1.body.toString('utf8'));
    assert.equal(j1.url, '/inspect?x=1');
    assert.equal(j1.host, `127.0.0.1:${backendPort}`);
    assert.deepEqual(r1.headers['set-cookie'], ['a=1; Path=/', 'b=2; HttpOnly']);

    // 2. Chunked streaming response
    const r2 = await sendHttpOverYamux(clientSession, {
      method: 'GET',
      path: '/stream',
      headers: { host: 'public.moer.eu.org' },
    });
    assert.equal(r2.statusCode, 200);
    assert.equal(r2.body.toString('utf8'), 'part-1|part-2|part-3');

    // 3. Binary POST echo
    const postData = Buffer.alloc(100_000, 0xab);
    const r3 = await sendHttpOverYamux(
      clientSession,
      {
        method: 'POST',
        path: '/echo',
        headers: { host: 'public.moer.eu.org' },
      },
      postData,
    );
    assert.equal(r3.statusCode, 200);
    assert.ok(r3.body.equals(postData));

    // 4. WebSocket upgrade through Yamux
    const wsStream = clientSession.openStream();
    wsStream.remoteAddress = '127.0.0.1';
    wsStream.setTimeout = () => wsStream;
    wsStream.setNoDelay = () => wsStream;
    wsStream.setKeepAlive = () => wsStream;
    wsStream.destroySoon = () => wsStream.end();

    const ws = new WebSocket('ws://public.moer.eu.org/ws', {
      createConnection: () => wsStream,
    });
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });

    const textReply = await new Promise((resolve) => {
      ws.once('message', (d) => resolve(d.toString('utf8')));
      ws.send('hello-ws');
    });
    assert.equal(textReply, 'ws-echo:hello-ws');

    const binReply = await new Promise((resolve) => {
      ws.once('message', (d) => resolve(Buffer.from(d)));
      ws.send(Buffer.from([1, 2, 3]), { binary: true });
    });
    assert.deepEqual(binReply, Buffer.from([98, 105, 110, 58, 1, 2, 3]));
    await new Promise((resolve) => {
      ws.once('close', resolve);
      ws.close();
    });

    // 5. WebSocket upgrade rejected with 403
    const wsRejectStream = clientSession.openStream();
    wsRejectStream.remoteAddress = '127.0.0.1';
    wsRejectStream.setTimeout = () => wsRejectStream;
    wsRejectStream.setNoDelay = () => wsRejectStream;
    wsRejectStream.setKeepAlive = () => wsRejectStream;
    wsRejectStream.destroySoon = () => wsRejectStream.end();

    const rejectStatus = await new Promise((resolve) => {
      const ws2 = new WebSocket('ws://public.moer.eu.org/ws-reject', {
        createConnection: () => wsRejectStream,
      });
      ws2.once('unexpected-response', (_req, res) => {
        res.resume();
        resolve(res.statusCode);
      });
    });
    assert.equal(rejectStatus, 403);

    assert.ok(events.some((e) => e.method === 'WS' && e.status === 101 && e.isWebSocket));
  } finally {
    await clientSession.close();
    await serverSession.close();
    for (const c of wss.clients) c.terminate();
    wss.close();
    backend.closeAllConnections?.();
    await new Promise((r) => backend.close(r));
  }
});

test('LocalForwarder preserve/custom Host header, basePath, and 502 on unreachable target', async () => {
  const backend = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ url: req.url, host: req.headers.host }));
  });
  await new Promise((r) => backend.listen(0, '127.0.0.1', r));
  const port = backend.address().port;

  let backendClosed = false;
  const closeBackend = async () => {
    if (!backendClosed) {
      backendClosed = true;
      await new Promise((r) => backend.close(r));
    }
  };

  try {
    // Test preserve + basePath
    const [a1, b1] = createDuplexPair();
    const c1 = new YamuxSession(a1, { mode: 'client' });
    const s1 = new YamuxSession(b1, { mode: 'server' });
    const f1 = new LocalForwarder(
      createTargetConfig(normalizeTargetUrl(`http://127.0.0.1:${port}/prefix`), {
        hostHeader: 'preserve',
      }),
    );
    s1.on('stream', (stream) => f1.handleStream(stream));

    const res1 = await sendHttpOverYamux(c1, {
      method: 'GET',
      path: '/hello',
      headers: { host: 'kept.moer.eu.org' },
    });
    assert.deepEqual(JSON.parse(res1.body.toString('utf8')), {
      url: '/prefix/hello',
      host: 'kept.moer.eu.org',
    });
    await c1.close();
    await s1.close();

    // Test custom Host header
    const [a2, b2] = createDuplexPair();
    const c2 = new YamuxSession(a2, { mode: 'client' });
    const s2 = new YamuxSession(b2, { mode: 'server' });
    const f2 = new LocalForwarder(
      createTargetConfig(normalizeTargetUrl(`http://127.0.0.1:${port}`), {
        hostHeader: 'internal.local:9999',
      }),
    );
    s2.on('stream', (stream) => f2.handleStream(stream));

    const res2 = await sendHttpOverYamux(c2, {
      method: 'GET',
      path: '/',
      headers: { host: 'ignored.moer.eu.org' },
    });
    assert.equal(JSON.parse(res2.body.toString('utf8')).host, 'internal.local:9999');
    await c2.close();
    await s2.close();
    await closeBackend();

    // Test unreachable target -> 502 without closing Yamux session
    const [a3, b3] = createDuplexPair();
    const c3 = new YamuxSession(a3, { mode: 'client' });
    const s3 = new YamuxSession(b3, { mode: 'server' });
    const f3 = new LocalForwarder(
      createTargetConfig(normalizeTargetUrl(`http://127.0.0.1:${port}`)), // port is now closed!
    );
    s3.on('stream', (stream) => f3.handleStream(stream));

    const res3 = await sendHttpOverYamux(c3, { method: 'GET', path: '/down' });
    assert.equal(res3.statusCode, 502);
    assert.match(res3.body.toString('utf8'), /^neruton: failed to connect to local service/);
    assert.equal(c3.isClosed, false);

    await c3.close();
    await s3.close();
  } finally {
    await closeBackend();
  }
});

test('Regression: upgraded backend sending >256 KiB then closing drains cleanly with FIN (no RST/truncation)', async () => {
  const payload = crypto.randomBytes(280 * 1024); // 286,720 bytes > 256 KiB Yamux window
  const backend = http.createServer((_req, res) => {
    res.writeHead(404);
    res.end();
  });
  backend.on('upgrade', (_req, socket) => {
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\nConnection: Upgrade\r\n\r\n',
    );
    socket.end(payload);
  });
  await new Promise((r) => backend.listen(0, '127.0.0.1', r));
  const port = backend.address().port;

  // Sniff frames flowing from server -> client to confirm FIN and zero RST
  const serverToClientFrames = [];
  const sniffer = new YamuxFrameDecoder();
  const [a, b] = createDuplexPair();
  a.on('data', (chunk) => {
    serverToClientFrames.push(...sniffer.push(Buffer.from(chunk)));
  });

  const clientSession = new YamuxSession(a, { mode: 'client' });
  const serverSession = new YamuxSession(b, { mode: 'server' });
  const forwarder = new LocalForwarder(
    createTargetConfig(normalizeTargetUrl(`http://127.0.0.1:${port}`)),
  );
  serverSession.on('stream', (stream) => forwarder.handleStream(stream));

  try {
    const stream = clientSession.openStream();
    stream.write(
      'GET /raw HTTP/1.1\r\nHost: pub.test\r\nConnection: Upgrade\r\nUpgrade: raw\r\n\r\n',
    );

    // Slow reader: wait 80ms so backend finishes socket.end() while Yamux sendWindow hits 0
    await new Promise((r) => setTimeout(r, 80));

    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.from(chunk));
    }
    const raw = Buffer.concat(chunks);
    const sepIdx = raw.indexOf('\r\n\r\n');
    assert.ok(sepIdx > 0, 'expected 101 header block');
    const headStr = raw.subarray(0, sepIdx).toString('utf8');
    assert.match(headStr, /^HTTP\/1\.1 101 Switching Protocols/);
    const body = raw.subarray(sepIdx + 4);
    assert.equal(body.length, payload.length, 'must receive all 280 KiB without truncation');
    assert.ok(body.equals(payload), 'payload bytes must match exactly');

    const stream1Frames = serverToClientFrames.filter(
      (f) => f.header.streamId === 1 && f.header.type === YamuxFrameType.Data,
    );
    assert.ok(
      stream1Frames.some((f) => (f.header.flags & YamuxFlag.FIN) !== 0),
      'expected clean FIN on stream 1',
    );
    assert.equal(
      stream1Frames.some((f) => (f.header.flags & YamuxFlag.RST) !== 0),
      false,
      'must not emit RST on clean backend close',
    );
  } finally {
    await clientSession.close();
    await serverSession.close();
    backend.closeAllConnections?.();
    await new Promise((r) => backend.close(r));
  }
});

test('Regression: early 413 response before keep-alive POST body finishes forces Connection: close with no trailing 400 or smuggling', async () => {
  const seenUrls = [];
  const backend = http.createServer((req, res) => {
    seenUrls.push(req.url);
    res.writeHead(413, 'Payload Too Large', {
      'content-type': 'text/plain',
      'content-length': '3',
    });
    res.end('413');
  });
  await new Promise((r) => backend.listen(0, '127.0.0.1', r));
  const port = backend.address().port;

  const [a, b] = createDuplexPair();
  const clientSession = new YamuxSession(a, { mode: 'client' });
  const serverSession = new YamuxSession(b, { mode: 'server' });
  const forwarder = new LocalForwarder(
    createTargetConfig(normalizeTargetUrl(`http://127.0.0.1:${port}`)),
  );
  serverSession.on('stream', (stream) => forwarder.handleStream(stream));

  try {
    const stream = clientSession.openStream();
    const smuggled = 'GET /smuggled HTTP/1.1\r\nHost: evil\r\n\r\n';
    // Claim Content-Length: 4096, write only partial body containing a smuggled HTTP request,
    // then pause before closing write half once the 413 arrives.
    stream.write(
      `POST /upload HTTP/1.1\r\nHost: pub.test\r\nConnection: keep-alive\r\nContent-Length: 4096\r\n\r\n${smuggled}`,
    );

    const chunks = [];
    const done = new Promise((resolve) => {
      stream.on('data', (c) => {
        chunks.push(Buffer.from(c));
        // Simulate client closing its write half right after seeing the early 413
        if (!stream.writableEnded) {
          stream.end();
        }
      });
      stream.on('end', resolve);
    });
    await done;

    const rawResponse = Buffer.concat(chunks).toString('utf8');
    assert.match(rawResponse, /^HTTP\/1\.1 413 Payload Too Large\r\n/);
    assert.match(rawResponse, /\r\nConnection: close\r\n/i);
    assert.ok(rawResponse.endsWith('\r\n\r\n413'), `unexpected trailing bytes: ${JSON.stringify(rawResponse)}`);
    assert.equal(rawResponse.includes('400 Bad Request'), false, 'must not append bogus 400 Bad Request');
    assert.deepEqual(seenUrls, ['/upload'], 'must not forward smuggled request');
  } finally {
    await clientSession.close();
    await serverSession.close();
    backend.closeAllConnections?.();
    await new Promise((r) => backend.close(r));
  }
});
