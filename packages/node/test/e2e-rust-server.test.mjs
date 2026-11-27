import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import WebSocket, { WebSocketServer } from 'ws';
import {
  AuthenticationError,
  VERSION,
  connect,
  forward,
  loadConfig,
  saveConfig,
} from '../dist/esm/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const serverBinary = path.join(repoRoot, 'target', 'debug', 'neruton-server');
const cliBinary = path.join(repoRoot, 'target', 'debug', 'neruton');

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
    srv.on('error', reject);
  });
}

function httpRequest(port, { method = 'GET', path: reqPath = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: reqPath, headers }, (res) => {
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

async function waitForHealth(port, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await httpRequest(port, { path: '/_neruton/health' });
      if (res.statusCode === 200) {
        return JSON.parse(res.body.toString('utf8'));
      }
    } catch {
      // Server not listening yet.
    }
    await new Promise((r) => setTimeout(r, 80));
  }
  throw new Error(`neruton-server did not become healthy on port ${port}`);
}

const largeDownloadPayload = crypto.randomBytes(1536 * 1024 + 321); // 1.5 MiB

function startLocalBackend() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const parsed = new URL(req.url || '/', 'http://127.0.0.1');

      if (parsed.pathname === '/hello') {
        const xfh = req.headers['x-forwarded-host'] || '';
        const host = req.headers.host || '';
        res.writeHead(200, {
          'content-type': 'text/plain; charset=utf-8',
          'x-backend': 'node-ok',
        });
        res.end(`hello|q=${parsed.searchParams.toString()}|xfh=${xfh}|host=${host}`);
        return;
      }

      if (parsed.pathname === '/echo' && req.method === 'POST') {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
          const buf = Buffer.concat(chunks);
          res.writeHead(200, {
            'content-type': 'application/octet-stream',
            'content-length': String(buf.length),
          });
          res.end(buf);
        });
        return;
      }

      if (parsed.pathname === '/stream') {
        res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
        res.write('chunk-1|');
        setTimeout(() => {
          res.write('chunk-2|');
          setTimeout(() => res.end('chunk-3'), 15);
        }, 15);
        return;
      }

      if (parsed.pathname === '/page') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><html><head><title>Demo</title></head><body>Hello Node E2E</body></html>');
        return;
      }

      if (parsed.pathname === '/large') {
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-length': String(largeDownloadPayload.length),
        });
        res.end(largeDownloadPayload);
        return;
      }

      res.writeHead(404);
      res.end('not found');
    });

    const wss = new WebSocketServer({ noServer: true });
    server.on('upgrade', (req, socket, head) => {
      if (req.url === '/ws') {
        wss.handleUpgrade(req, socket, head, (ws) => {
          ws.on('message', (data, isBinary) => {
            if (isBinary) {
              ws.send(data, { binary: true });
            } else {
              ws.send(`echo:${data.toString('utf8')}`);
            }
          });
        });
      } else {
        socket.destroy();
      }
    });

    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        close: () =>
          new Promise((done) => {
            for (const c of wss.clients) c.terminate();
            wss.close(() => server.close(() => done()));
          }),
      });
    });
  });
}

test(
  'E2E against real Rust target/debug/neruton-server (auth, Yamux flow control, HTTP, WS, path proxy, token disable)',
  { skip: !fs.existsSync(serverBinary) && `missing ${serverBinary}` },
  async () => {
    const serverPort = await getFreePort();
    const deadPort = await getFreePort();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-node-e2e-'));
    const backend = await startLocalBackend();

    const serverProc = spawn(
      serverBinary,
      [
        '--bind',
        `127.0.0.1:${serverPort}`,
        '--base-domain',
        'moer.eu.org',
        '--panel-host',
        'neruton.moer.eu.org',
        '--public-scheme',
        'http',
        '--data-dir',
        dataDir,
        '--require-auth',
        'true',
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );

    let serverStderr = '';
    serverProc.stderr.on('data', (d) => {
      serverStderr += d.toString('utf8');
    });

    const openTunnels = [];
    try {
      const health = await waitForHealth(serverPort);
      assert.equal(health.status, 'ok');
      assert.equal(health.auth_required, true);

      // 1. Setup admin account & obtain real `ntk_...` tunnel token + session cookie
      const setupPayload = JSON.stringify({
        username: 'admin',
        password: 'AdminPassword123!',
      });
      const setupRes = await httpRequest(serverPort, {
        method: 'POST',
        path: '/_neruton/api/auth/setup',
        headers: {
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(setupPayload)),
        },
        body: setupPayload,
      });
      assert.equal(setupRes.statusCode, 201, `setup failed: ${setupRes.body.toString()}`);
      const setupJson = JSON.parse(setupRes.body.toString('utf8'));
      const userToken = setupJson.initial_token.secret;
      const tokenId = setupJson.initial_token.token.id;
      assert.ok(userToken.startsWith('ntk_'));

      const setCookie = setupRes.headers['set-cookie']?.[0];
      assert.ok(setCookie, 'expected session cookie');
      const cookieHeader = setCookie.split(';')[0];

      // 2. 401 fail-fast without token & with invalid token
      await assert.rejects(
        () =>
          connect({
            url: backend.port,
            server: `http://127.0.0.1:${serverPort}`,
            subdomain: 'anon-fail',
            retryInitialConnect: true,
          }),
        (err) => err instanceof AuthenticationError && err.statusCode === 401,
      );

      await assert.rejects(
        () =>
          connect({
            url: backend.port,
            server: `http://127.0.0.1:${serverPort}`,
            subdomain: 'bad-tok',
            token: 'ntk_invalid_token',
            retryInitialConnect: true,
          }),
        (err) => err instanceof AuthenticationError && err.statusCode === 401,
      );

      // 3. Connect custom-subdomain tunnel & auto-UUID tunnel via forward()
      const tunnel = await connect({
        url: `http://127.0.0.1:${backend.port}`,
        server: `http://127.0.0.1:${serverPort}`,
        token: userToken,
        subdomain: 'node-e2e',
        reconnectInitialDelayMs: 150,
      });
      openTunnels.push(tunnel);

      assert.equal(tunnel.prefix, 'node-e2e');
      assert.equal(tunnel.publicUrl, 'http://node-e2e.moer.eu.org');
      assert.equal(tunnel.pathUrl, 'http://neruton.moer.eu.org/t/node-e2e/');
      assert.equal(tunnel.previewUrl, 'http://neruton.moer.eu.org/preview/node-e2e');
      assert.equal(tunnel.ownerUsername, 'admin');
      assert.equal(tunnel.tokenName, 'Default CLI Token');

      const requestEvents = [];
      tunnel.on('request', (ev) => requestEvents.push(ev));

      const uuidTunnel = await forward(backend.port, {
        server: `http://127.0.0.1:${serverPort}`,
        token: userToken,
      });
      openTunnels.push(uuidTunnel);
      assert.match(
        uuidTunnel.prefix,
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );

      // 4. Wildcard Host GET + query + header check
      const rHello = await httpRequest(serverPort, {
        path: '/hello?foo=bar',
        headers: { host: 'node-e2e.moer.eu.org' },
      });
      assert.equal(rHello.statusCode, 200);
      assert.equal(rHello.headers['x-backend'], 'node-ok');
      assert.equal(
        rHello.body.toString('utf8'),
        `hello|q=foo=bar|xfh=node-e2e.moer.eu.org|host=127.0.0.1:${backend.port}`,
      );

      // 5. Large 512 KiB POST upload AND 1.5 MiB GET download (>6x Yamux 256 KiB window -> bidirectional flow control!)
      const largeBody = crypto.randomBytes(512 * 1024 + 777);
      const rEcho = await httpRequest(serverPort, {
        method: 'POST',
        path: '/echo',
        headers: {
          host: 'node-e2e.moer.eu.org',
          'content-length': String(largeBody.length),
        },
        body: largeBody,
      });
      assert.equal(rEcho.statusCode, 200);
      assert.equal(rEcho.body.length, largeBody.length);
      assert.ok(rEcho.body.equals(largeBody), '512 KiB upload payload mismatch through Rust Yamux');

      const rLarge = await httpRequest(serverPort, {
        method: 'GET',
        path: '/large',
        headers: { host: 'node-e2e.moer.eu.org' },
      });
      assert.equal(rLarge.statusCode, 200);
      assert.equal(rLarge.body.length, largeDownloadPayload.length);
      assert.ok(rLarge.body.equals(largeDownloadPayload), '1.5 MiB download payload mismatch through Rust Yamux');

      // 6. Streaming chunked response
      const rStream = await httpRequest(serverPort, {
        path: '/stream',
        headers: { host: 'node-e2e.moer.eu.org' },
      });
      assert.equal(rStream.statusCode, 200);
      assert.equal(rStream.body.toString('utf8'), 'chunk-1|chunk-2|chunk-3');

      // 7. Path proxy mode (/t/node-e2e/page) injects <base href="/t/node-e2e/">
      const rPath = await httpRequest(serverPort, {
        path: '/t/node-e2e/page',
        headers: { host: 'neruton.moer.eu.org' },
      });
      assert.equal(rPath.statusCode, 200);
      const pageHtml = rPath.body.toString('utf8');
      assert.ok(pageHtml.includes('<base href="/t/node-e2e/">'));
      assert.ok(pageHtml.includes('Hello Node E2E'));

      // 8. 20 concurrent multiplexed HTTP requests over single Yamux session
      const concurrentResults = await Promise.all(
        Array.from({ length: 20 }, (_, i) =>
          httpRequest(serverPort, {
            path: `/hello?idx=${i}`,
            headers: { host: 'node-e2e.moer.eu.org' },
          }),
        ),
      );
      for (let i = 0; i < concurrentResults.length; i += 1) {
        assert.equal(concurrentResults[i].statusCode, 200);
        assert.ok(concurrentResults[i].body.toString('utf8').includes(`q=idx=${i}`));
      }

      // 9. WebSocket upgrade end-to-end through Rust server -> Yamux -> Node SDK -> local backend
      const ws = new WebSocket(`ws://127.0.0.1:${serverPort}/ws`, {
        headers: { Host: 'node-e2e.moer.eu.org' },
      });
      await new Promise((resolve, reject) => {
        ws.once('open', resolve);
        ws.once('error', reject);
      });
      for (const msg of ['ping-1', 'hello-neruton', 'multi-frame']) {
        const reply = await new Promise((resolve, reject) => {
          ws.once('message', (d) => resolve(d.toString('utf8')));
          ws.once('error', reject);
          ws.send(msg);
        });
        assert.equal(reply, `echo:${msg}`);
      }
      ws.close();

      // 10. Local unreachable backend -> 502 without dropping tunnel
      const downTunnel = await connect({
        url: deadPort,
        server: `http://127.0.0.1:${serverPort}`,
        token: userToken,
        subdomain: 'down-backend',
      });
      openTunnels.push(downTunnel);

      const r502 = await httpRequest(serverPort, {
        path: '/anything',
        headers: { host: 'down-backend.moer.eu.org' },
      });
      assert.equal(r502.statusCode, 502);
      assert.match(r502.body.toString('utf8'), /neruton: failed to connect to local service/);
      assert.equal(downTunnel.connected, true);

      // 11. Wait briefly for server's 200ms WS keepalive ping and inspect server tunnel API
      await new Promise((r) => setTimeout(r, 300));
      const infoRes = await httpRequest(serverPort, {
        path: '/_neruton/api/tunnels/node-e2e',
        headers: { cookie: cookieHeader },
      });
      assert.equal(infoRes.statusCode, 200);
      const info = JSON.parse(infoRes.body.toString('utf8'));
      assert.equal(info.prefix, 'node-e2e');
      assert.equal(info.client_version, VERSION);
      assert.equal(info.owner_username, 'admin');
      assert.equal(info.token_name, 'Default CLI Token');
      assert.ok(info.requests_total >= 24);
      assert.ok(requestEvents.some((e) => e.isWebSocket && e.status === 101));

      // 11b. Reconnect recovery: server force-disconnects tunnel via DELETE /_neruton/api/tunnels/:prefix
      //      and Node SDK automatically reconnects with the SAME sticky prefix and resumes traffic!
      const reconnectedPromise = new Promise((resolve) => {
        tunnel.once('connected', resolve);
      });
      const delRes = await httpRequest(serverPort, {
        method: 'DELETE',
        path: '/_neruton/api/tunnels/node-e2e',
        headers: { cookie: cookieHeader },
      });
      assert.equal(delRes.statusCode, 200);
      const reconnectedEv = await reconnectedPromise;
      assert.equal(reconnectedEv.reconnected, true);
      assert.equal(reconnectedEv.prefix, 'node-e2e');

      const rAfterReconnect = await httpRequest(serverPort, {
        path: '/hello?after=reconnect',
        headers: { host: 'node-e2e.moer.eu.org' },
      });
      assert.equal(rAfterReconnect.statusCode, 200);
      assert.ok(rAfterReconnect.body.toString('utf8').includes('q=after=reconnect'));

      // 12. Clean close removes tunnel on server
      await uuidTunnel.close();
      await downTunnel.close();
      await new Promise((r) => setTimeout(r, 100));
      const afterClose = await httpRequest(serverPort, {
        path: `/_neruton/api/tunnels/${uuidTunnel.prefix}`,
        headers: { cookie: cookieHeader },
      });
      assert.equal(afterClose.statusCode, 404);

      // 13. Disabling token disconnects active tunnel & reconnect gets 401 fail-fast!
      const errPromise = new Promise((resolve) => tunnel.once('error', resolve));
      const disableBody = JSON.stringify({ enabled: false });
      const disableRes = await httpRequest(serverPort, {
        method: 'PATCH',
        path: `/_neruton/api/tokens/${tokenId}`,
        headers: {
          cookie: cookieHeader,
          'content-type': 'application/json',
          'content-length': String(Buffer.byteLength(disableBody)),
        },
        body: disableBody,
      });
      assert.equal(disableRes.statusCode, 200);

      const [errEmitted] = await Promise.all([
        errPromise,
        assert.rejects(() => tunnel.wait(), (e) => e instanceof AuthenticationError),
      ]);
      assert.ok(errEmitted instanceof AuthenticationError);
      assert.equal(tunnel.closed, true);
    } finally {
      for (const t of openTunnels) {
        await t.close().catch(() => {});
      }
      serverProc.kill('SIGTERM');
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          serverProc.kill('SIGKILL');
          resolve();
        }, 3000);
        serverProc.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
      await backend.close();
      fs.rmSync(dataDir, { recursive: true, force: true });
      if (serverStderr && process.env.DEBUG_E2E) {
        console.error(serverStderr);
      }
    }
  },
);

test(
  'Config TOML interop with real Rust target/debug/neruton CLI',
  { skip: !fs.existsSync(cliBinary) && `missing ${cliBinary}` },
  () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-cfg-interop-'));
    const cfgFile = path.join(tmpDir, 'config.toml');
    try {
      // 1. Written by Rust CLI -> read by Node SDK
      execFileSync(cliBinary, [
        'config',
        'set',
        '--server',
        'https://rust.example.test',
        '--token',
        'ntk_from_rust_123',
        '--config',
        cfgFile,
      ]);
      const loaded = loadConfig(cfgFile);
      assert.deepEqual(loaded, {
        server: 'https://rust.example.test',
        token: 'ntk_from_rust_123',
      });

      // 2. Written by Node SDK -> read by Rust CLI
      saveConfig({ server: 'https://node.example.test', token: 'ntk_from_node_456' }, cfgFile);
      const rustShow = execFileSync(cliBinary, ['config', 'show', '--config', cfgFile], {
        encoding: 'utf8',
        env: { ...process.env, NERUTON_SERVER: '', NERUTON_TOKEN: '', NERUTON_AUTH_TOKEN: '' },
      });
      assert.match(rustShow, /Effective server:\s+https:\/\/node\.example\.test/);
      assert.match(rustShow, /Saved server:\s+https:\/\/node\.example\.test/);
      assert.match(rustShow, /Saved token:\s+<configured>/);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  },
);

test('Local HTTPS target forwarding with self-signed cert and noTlsVerify: true', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-tls-test-'));
  const keyPath = path.join(tmpDir, 'key.pem');
  const certPath = path.join(tmpDir, 'cert.pem');
  try {
    try {
      execFileSync('openssl', [
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
        '/CN=127.0.0.1',
      ], { stdio: 'ignore' });
    } catch {
      t.skip('openssl not available');
      return;
    }

    const tlsBackend = https.createServer(
      { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) },
      (req, res) => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end(`https-ok:${req.url}:${req.headers.host}`);
      },
    );
    await new Promise((r) => tlsBackend.listen(0, '127.0.0.1', r));
    const tlsPort = tlsBackend.address().port;

    const serverPort = await getFreePort();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'neruton-tls-srv-'));
    const serverProc = spawn(
      serverBinary,
      [
        '--bind',
        `127.0.0.1:${serverPort}`,
        '--base-domain',
        'moer.eu.org',
        '--panel-host',
        'neruton.moer.eu.org',
        '--public-scheme',
        'http',
        '--data-dir',
        dataDir,
        '--require-auth',
        'false',
      ],
      { stdio: ['ignore', 'ignore', 'ignore'] },
    );

    let tunnel;
    try {
      await waitForHealth(serverPort);
      tunnel = await connect({
        url: `https://127.0.0.1:${tlsPort}`,
        server: `http://127.0.0.1:${serverPort}`,
        subdomain: 'tls-local',
        noTlsVerify: true,
      });

      const res = await httpRequest(serverPort, {
        path: '/secret',
        headers: { host: 'tls-local.moer.eu.org' },
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.toString('utf8'), `https-ok:/secret:127.0.0.1:${tlsPort}`);
    } finally {
      await tunnel?.close().catch(() => {});
      if (serverProc.exitCode === null) {
        serverProc.kill('SIGTERM');
        await new Promise((resolve) => {
          const timer = setTimeout(() => {
            serverProc.kill('SIGKILL');
            resolve();
          }, 3000);
          serverProc.once('exit', () => {
            clearTimeout(timer);
            resolve();
          });
        });
      }
      tlsBackend.closeAllConnections?.();
      await new Promise((r) => tlsBackend.close(r));
      fs.rmSync(dataDir, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
