import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { Duplex } from 'node:stream';
import {
  YAMUX_DEFAULT_WINDOW,
  YAMUX_HEADER_SIZE,
  YamuxFlag,
  YamuxFrameDecoder,
  YamuxFrameType,
  YamuxGoAwayCode,
  YamuxSession,
  decodeYamuxHeader,
  encodeYamuxFrame,
  encodeYamuxHeader,
} from '../dist/esm/index.js';

function createDuplexPair() {
  let peerA;
  let peerB;

  peerA = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      if (peerB.destroyed) {
        cb(new Error('peer closed'));
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
        cb(new Error('peer closed'));
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

function readAll(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (c) => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

test('Yamux header encode/decode matches yamux 0.13 big-endian wire format byte-for-byte', () => {
  const hdr = encodeYamuxHeader({
    type: YamuxFrameType.Data,
    flags: YamuxFlag.SYN | YamuxFlag.FIN,
    streamId: 0x01020304,
    length: 0x00040000,
  });

  assert.equal(hdr.length, YAMUX_HEADER_SIZE);
  assert.deepEqual(
    hdr,
    Buffer.from([
      0x00, // version 0
      0x00, // type Data
      0x00, 0x05, // flags SYN(1) | FIN(4)
      0x01, 0x02, 0x03, 0x04, // stream_id
      0x00, 0x04, 0x00, 0x00, // length (256 KiB)
    ]),
  );

  const decoded = decodeYamuxHeader(hdr);
  assert.deepEqual(decoded, {
    version: 0,
    type: YamuxFrameType.Data,
    flags: YamuxFlag.SYN | YamuxFlag.FIN,
    streamId: 0x01020304,
    length: 262144,
  });

  const pingHdr = encodeYamuxHeader({
    type: YamuxFrameType.Ping,
    flags: YamuxFlag.ACK,
    streamId: 0,
    length: 0xdeadbeef,
  });
  assert.deepEqual(
    pingHdr,
    Buffer.from([0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef]),
  );
  assert.equal(decodeYamuxHeader(pingHdr).length, 0xdeadbeef);

  assert.throws(() => decodeYamuxHeader(Buffer.from([1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])), /version/);
  assert.throws(() => decodeYamuxHeader(Buffer.from([0, 9, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0])), /frame type/);
});

test('YamuxFrameDecoder handles 1-byte chunks and coalesced multi-frame buffers', () => {
  const f1 = encodeYamuxFrame(YamuxFrameType.Data, YamuxFlag.SYN, 1, Buffer.from('hello'));
  const f2 = encodeYamuxFrame(YamuxFrameType.WindowUpdate, YamuxFlag.ACK, 1, 131072);
  const f3 = encodeYamuxFrame(YamuxFrameType.Ping, YamuxFlag.SYN, 0, 42);
  const f4 = encodeYamuxFrame(YamuxFrameType.GoAway, YamuxFlag.NONE, 0, YamuxGoAwayCode.Normal);
  const combined = Buffer.concat([f1, f2, f3, f4]);

  const dec1 = new YamuxFrameDecoder();
  const out1 = [];
  for (let i = 0; i < combined.length; i += 1) {
    out1.push(...dec1.push(combined.subarray(i, i + 1)));
  }
  assert.equal(out1.length, 4);
  assert.equal(out1[0].body.toString('utf8'), 'hello');
  assert.equal(out1[1].header.type, YamuxFrameType.WindowUpdate);
  assert.equal(out1[1].header.length, 131072);
  assert.equal(out1[2].header.type, YamuxFrameType.Ping);
  assert.equal(out1[2].header.length, 42);
  assert.equal(out1[3].header.type, YamuxFrameType.GoAway);
  assert.equal(out1[3].header.length, 0);

  const dec2 = new YamuxFrameDecoder();
  const out2 = dec2.push(combined);
  assert.equal(out2.length, 4);
  assert.equal(dec2.bufferedBytes, 0);
});

test('YamuxSession client/server stream ID parity, lazy SYN/ACK, and half-close FIN', async () => {
  const [a, b] = createDuplexPair();
  const client = new YamuxSession(a, { mode: 'client' });
  const server = new YamuxSession(b, { mode: 'server' });

  const inboundIds = [];
  server.on('stream', (stream) => {
    inboundIds.push(stream.id);
    // Echo server: wait for full client half-close FIN before replying
    void readAll(stream).then((data) => {
      stream.end(Buffer.concat([Buffer.from('echo:'), data]));
    });
  });

  const s1 = client.openStream();
  const s2 = client.openStream();
  assert.equal(s1.id, 1);
  assert.equal(s2.id, 3);

  const p1 = readAll(s1);
  const p2 = readAll(s2);

  s1.end('first');
  s2.end('second');

  const [r1, r2] = await Promise.all([p1, p2]);
  assert.equal(r1.toString('utf8'), 'echo:first');
  assert.equal(r2.toString('utf8'), 'echo:second');
  assert.deepEqual(inboundIds, [1, 3]);

  // Also test server -> client even stream IDs
  const clientInbound = [];
  client.on('stream', (stream) => {
    clientInbound.push(stream.id);
    stream.pipe(stream);
  });

  const sServer = server.openStream();
  assert.equal(sServer.id, 2);
  const pServer = readAll(sServer);
  sServer.end('from-server');
  assert.equal((await pServer).toString('utf8'), 'from-server');
  assert.deepEqual(clientInbound, [2]);

  await client.close();
  await server.close();
});

test('YamuxSession flow control: >1 MiB transfer across 256 KiB window emits WindowUpdate and enforces backpressure', async () => {
  const [a, b] = createDuplexPair();
  const client = new YamuxSession(a, { mode: 'client' });
  const server = new YamuxSession(b, { mode: 'server' });

  const payload = crypto.randomBytes(1024 * 1024 + 12345); // > 4x initial 256 KiB window
  assert.ok(payload.length > YAMUX_DEFAULT_WINDOW * 4);

  let serverStreamPromiseResolve;
  const serverStreamPromise = new Promise((r) => {
    serverStreamPromiseResolve = r;
  });

  server.on('stream', (stream) => {
    serverStreamPromiseResolve(stream);
  });

  const clientStream = client.openStream();
  const writeDone = new Promise((resolve, reject) => {
    clientStream.end(payload, (err) => (err ? reject(err) : resolve()));
  });

  const serverStream = await serverStreamPromise;

  // Before server reads, client sendWindow should hit 0 (backpressure active!)
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(clientStream.sendWindow, 0);

  // Now drain server stream slowly in chunks so WindowUpdates flow back
  const receivedChunks = [];
  for await (const chunk of serverStream) {
    receivedChunks.push(chunk);
  }
  await writeDone;

  const received = Buffer.concat(receivedChunks);
  assert.equal(received.length, payload.length);
  assert.ok(received.equals(payload));

  await client.close();
  await server.close();
});

test('YamuxSession concurrent multiplexing across 25 simultaneous streams', async () => {
  const [a, b] = createDuplexPair();
  const client = new YamuxSession(a, { mode: 'client' });
  const server = new YamuxSession(b, { mode: 'server' });

  server.on('stream', (stream) => {
    stream.pipe(stream);
  });

  const tasks = Array.from({ length: 25 }, async (_, i) => {
    const stream = client.openStream();
    const data = crypto.randomBytes(4096 + i * 2048);
    const resultPromise = readAll(stream);
    stream.end(data);
    const echoed = await resultPromise;
    assert.ok(echoed.equals(data), `stream ${i} payload mismatch`);
  });

  await Promise.all(tasks);
  await client.close();
  await server.close();
});

test('YamuxSession Ping(SYN) -> Ping(ACK), RST, WindowUpdate|SYN, and GoAway', async () => {
  const [a, b] = createDuplexPair();
  const client = new YamuxSession(a, { mode: 'client' });
  const server = new YamuxSession(b, { mode: 'server' });

  const rtt = await client.ping(0x12345678);
  assert.ok(rtt >= 0 && rtt < 5000);

  // Test RST handling
  let resetSeenOnServer = false;
  server.on('stream', (stream) => {
    stream.on('error', () => {});
    stream.on('end', () => {
      resetSeenOnServer = true;
    });
    stream.resume();
  });

  const s = client.openStream();
  s.on('error', () => {});
  s.write('hello');
  await new Promise((r) => setTimeout(r, 20));
  s.destroy(new Error('abort'));
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(resetSeenOnServer, true);

  // Test GoAway event
  let goAwayCode = null;
  server.on('goAway', (code) => {
    goAwayCode = code;
  });
  await client.close(YamuxGoAwayCode.Normal);
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(goAwayCode, YamuxGoAwayCode.Normal);
  assert.equal(server.isClosed, true);
});

test('YamuxSession opens stream via WindowUpdate|SYN with extra credit and rejects bad parity with GoAway', async () => {
  const [a, b] = createDuplexPair();
  const server = new YamuxSession(b, { mode: 'server' });

  let acceptedStream = null;
  server.on('stream', (s) => {
    acceptedStream = s;
  });

  // Send WindowUpdate|SYN with streamId=1 and extra credit=65536
  a.write(encodeYamuxFrame(YamuxFrameType.WindowUpdate, YamuxFlag.SYN, 1, 65536));
  await new Promise((r) => setTimeout(r, 20));

  assert.ok(acceptedStream);
  assert.equal(acceptedStream.id, 1);
  assert.equal(acceptedStream.sendWindow, YAMUX_DEFAULT_WINDOW + 65536);

  // Now send invalid even streamId=2 to server -> expects GoAway(ProtocolError)
  const receivedFrames = [];
  const dec = new YamuxFrameDecoder();
  a.on('data', (chunk) => {
    receivedFrames.push(...dec.push(chunk));
  });
  server.on('error', () => {});

  a.write(encodeYamuxFrame(YamuxFrameType.Data, YamuxFlag.SYN, 2, Buffer.from('bad')));
  await new Promise((r) => setTimeout(r, 20));

  const goAway = receivedFrames.find((f) => f.header.type === YamuxFrameType.GoAway);
  assert.ok(goAway, 'expected GoAway frame on invalid stream parity');
  assert.equal(goAway.header.length, YamuxGoAwayCode.ProtocolError);
});

test('Regression: custom initialWindow keeps peer sendWindow at 256 KiB and _destroy does not double-decrement unackedInboundCount', async () => {
  const [a, b] = createDuplexPair();
  const client = new YamuxSession(a, { mode: 'client', initialWindow: 512 * 1024 });
  const server = new YamuxSession(b, { mode: 'server', initialWindow: 512 * 1024 });

  const outStream = client.openStream();
  assert.equal(outStream.sendWindow, YAMUX_DEFAULT_WINDOW);
  assert.equal(outStream.receiveWindow, 512 * 1024);

  // Open 10 inbound streams with SYN|FIN (immediately recv-closed) and destroy them cleanly;
  // unackedInboundCount should return to 0 and subsequent 64+ streams should still trigger eager ACK properly.
  const inboundStreams = [];
  server.on('stream', (s) => inboundStreams.push(s));

  for (let i = 0; i < 10; i += 1) {
    const s = client.openStream();
    s.end('hi');
  }
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(inboundStreams.length, 10);
  for (const s of inboundStreams) {
    assert.equal(s.sendWindow, YAMUX_DEFAULT_WINDOW);
    s.destroy();
  }
  await new Promise((r) => setTimeout(r, 20));

  // Verify unackedInboundCount did not underflow or corrupt eager ACK tracking
  const frames = [];
  const dec = new YamuxFrameDecoder();
  a.on('data', (c) => frames.push(...dec.push(Buffer.from(c))));

  const batch = [];
  for (let i = 0; i < 70; i += 1) {
    const s = client.openStream();
    s.write('x');
    batch.push(s);
  }
  await new Promise((r) => setTimeout(r, 40));

  const ackWindowUpdates = frames.filter(
    (f) =>
      f.header.type === YamuxFrameType.WindowUpdate &&
      (f.header.flags & YamuxFlag.ACK) !== 0 &&
      f.header.length === 0,
  );
  assert.ok(ackWindowUpdates.length >= 7, `expected eager ACKs for streams >= 64, got ${ackWindowUpdates.length}`);

  await client.close();
  await server.close();
});
