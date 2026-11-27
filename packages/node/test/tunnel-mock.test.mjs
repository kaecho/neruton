import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { WebSocketServer } from 'ws';
import {
  AuthenticationError,
  RegistrationError,
  VERSION,
  WsByteStream,
  YamuxSession,
  connect,
  forward,
  http as httpTunnel,
} from '../dist/esm/index.js';

function startMockServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(404);
      res.end();
    });
    const wss = new WebSocketServer({ noServer: true });

    server.on('upgrade', (req, socket, head) => {
      handler.onUpgrade(req, socket, head, wss);
    });

    server.listen(0, '127.0.0.1', () => {
      resolve({
        server,
        wss,
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

test('connect() fails fast on HTTP 401 without retrying', async () => {
  let attempts = 0;
  const mock = await startMockServer({
    onUpgrade(_req, socket) {
      attempts += 1;
      const body = JSON.stringify({ error: 'Invalid or revoked tunnel token.' });
      socket.write(
        `HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
      );
      socket.end();
    },
  });

  try {
    await assert.rejects(
      () =>
        connect({
          url: 3000,
          server: `http://127.0.0.1:${mock.port}`,
          token: 'ntk_bad',
          retryInitialConnect: true,
          reconnectInitialDelayMs: 50,
        }),
      (err) => {
        assert.ok(err instanceof AuthenticationError);
        assert.equal(err.statusCode, 401);
        assert.equal(err.serverMessage, 'Invalid or revoked tunnel token.');
        assert.equal(err.hadToken, true);
        return true;
      },
    );
    assert.equal(attempts, 1, '401 must fail fast on attempt 1');
  } finally {
    await mock.close();
  }
});

test('connect() fails fast on registration rejection (ok: false) on initial connect', async () => {
  let attempts = 0;
  const mock = await startMockServer({
    onUpgrade(req, socket, head, wss) {
      attempts += 1;
      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.once('message', () => {
          ws.send(
            JSON.stringify({
              ok: false,
              tunnel_id: '',
              prefix: '',
              public_url: '',
              path_url: '',
              preview_url: '',
              dashboard_url: '',
              error: "prefix 'bad' is not permitted by this token",
            }),
          );
          ws.close();
        });
      });
    },
  });

  try {
    await assert.rejects(
      () =>
        connect({
          url: 3000,
          server: `http://127.0.0.1:${mock.port}`,
          subdomain: 'bad',
          retryInitialConnect: true,
          reconnectInitialDelayMs: 50,
        }),
      (err) => {
        assert.ok(err instanceof RegistrationError);
        assert.equal(err.retryable, false);
        assert.match(err.message, /not permitted/);
        return true;
      },
    );
    assert.equal(attempts, 1);
  } finally {
    await mock.close();
  }
});

test('connect() handshake, sticky UUID reconnect, 401 fail-fast on reconnect, and Symbol.asyncDispose', async () => {
  const seenRequests = [];
  let connectionIndex = 0;
  let force401Next = false;

  const mock = await startMockServer({
    onUpgrade(req, socket, head, wss) {
      connectionIndex += 1;
      const idx = connectionIndex;
      if (force401Next) {
        const body = JSON.stringify({ error: 'Tunnel token is disabled.' });
        socket.write(
          `HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
        );
        socket.end();
        return;
      }

      wss.handleUpgrade(req, socket, head, (ws) => {
        ws.once('message', (data) => {
          const parsed = JSON.parse(data.toString('utf8'));
          seenRequests.push({
            auth: req.headers.authorization,
            path: req.url,
            body: parsed,
          });
          const assignedPrefix = parsed.prefix ?? '11111111-2222-4333-8444-555555555555';
          ws.send(
            JSON.stringify({
              ok: true,
              tunnel_id: `tid-${idx}`,
              prefix: assignedPrefix,
              public_url: `http://${assignedPrefix}.test.local`,
              path_url: `http://panel.test.local/t/${assignedPrefix}/`,
              preview_url: `http://panel.test.local/preview/${assignedPrefix}`,
              dashboard_url: 'http://panel.test.local',
              error: null,
              owner_username: 'alice',
              token_name: 'ci-token',
            }),
          );

          // Immediately transition to Yamux client mode and send a Yamux Ping back-to-back!
          const wsStream = new WsByteStream(ws);
          const yamux = new YamuxSession(wsStream, { mode: 'client' });
          void yamux.ping(idx).then(() => {
            if (idx === 1) {
              // Drop connection #1 to test auto-reconnect with sticky prefix
              ws.close(1012, 'restart');
            }
          }).catch(() => {});
        });
      });
    },
  });

  try {
    const tunnel = await forward(3456, {
      server: `http://127.0.0.1:${mock.port}`,
      token: 'ntk_live_token',
      reconnectInitialDelayMs: 40,
      reconnectMaxDelayMs: 100,
      keepaliveIntervalMs: 0,
    });

    assert.equal(tunnel.prefix, '11111111-2222-4333-8444-555555555555');
    assert.equal(tunnel.publicUrl, 'http://11111111-2222-4333-8444-555555555555.test.local');
    assert.equal(tunnel.previewUrl, 'http://panel.test.local/preview/11111111-2222-4333-8444-555555555555');
    assert.equal(tunnel.pathUrl, 'http://panel.test.local/t/11111111-2222-4333-8444-555555555555/');
    assert.equal(tunnel.ownerUsername, 'alice');
    assert.equal(tunnel.tokenName, 'ci-token');
    assert.equal(tunnel.connected, true);

    assert.equal(seenRequests[0].auth, 'Bearer ntk_live_token');
    assert.equal(seenRequests[0].path, '/_neruton/tunnel');
    assert.equal(seenRequests[0].body.prefix, null);
    assert.equal(seenRequests[0].body.target_url, 'http://127.0.0.1:3456/');
    assert.equal(seenRequests[0].body.client_version, VERSION);

    // Wait for reconnect #2
    const reconnectedEv = await new Promise((resolve) => {
      tunnel.once('connected', resolve);
    });
    assert.equal(reconnectedEv.reconnected, true);
    assert.equal(seenRequests[1].body.prefix, '11111111-2222-4333-8444-555555555555');

    // Test Symbol.asyncDispose clean close
    const disposeSym = Symbol.asyncDispose ?? Symbol.for('Symbol.asyncDispose');
    await tunnel[disposeSym]();
    assert.equal(tunnel.closed, true);
    await tunnel.wait();

    // Now test 401 during reconnect terminates wait() cleanly with AuthenticationError
    const tunnel2 = await httpTunnel(3456, {
      server: `http://127.0.0.1:${mock.port}`,
      token: 'ntk_will_revoke',
      reconnectInitialDelayMs: 30,
      keepaliveIntervalMs: 0,
    });
    force401Next = true;
    const errSeen = new Promise((resolve) => tunnel2.once('error', resolve));
    // Force drop all server sockets
    for (const c of mock.wss.clients) c.close(1008, 'revoked');

    const [emittedErr] = await Promise.all([
      errSeen,
      assert.rejects(() => tunnel2.wait(), (e) => e instanceof AuthenticationError),
    ]);
    assert.ok(emittedErr instanceof AuthenticationError);
    assert.equal(tunnel2.closed, true);
  } finally {
    await mock.close();
  }
});

test('Regression: AbortSignal firing as RegisterResponse resolves leaves zero zombie server WebSockets', async () => {
  let serverOpened = 0;
  let serverClosed = 0;
  let abortController;

  const mock = await startMockServer({
    onUpgrade(req, socket, head, wss) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        serverOpened += 1;
        ws.on('close', () => {
          serverClosed += 1;
        });
        ws.once('message', () => {
          ws.send(
            JSON.stringify({
              ok: true,
              tunnel_id: 'tid-race',
              prefix: 'race-prefix',
              public_url: 'http://race-prefix.test.local',
              path_url: 'http://panel.test.local/t/race-prefix/',
              preview_url: 'http://panel.test.local/preview/race-prefix',
              dashboard_url: 'http://panel.test.local',
              error: null,
            }),
            () => {
              // Abort right after RegisterResponse is flushed, hitting the exact post-handshake window!
              abortController.abort();
            },
          );
        });
      });
    },
  });

  try {
    for (let i = 0; i < 5; i += 1) {
      abortController = new AbortController();
      try {
        const t = await connect({
          url: 3000,
          server: `http://127.0.0.1:${mock.port}`,
          signal: abortController.signal,
          keepaliveIntervalMs: 50,
        });
        // If abort landed strictly after connect() resolved, close() must still tear down cleanly.
        await Promise.all([t.close(), t.close()]);
      } catch (err) {
        assert.equal(err.code, 'ABORTED');
      }
    }

    // Wait briefly for server close frames to arrive
    const deadline = Date.now() + 2000;
    while (serverClosed < serverOpened && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(serverClosed, serverOpened, `leaked server WS: opened=${serverOpened}, closed=${serverClosed}`);
  } finally {
    await mock.close();
  }
});

test('Regression: close() called while reconnect openSingleSession() resolves cleans up session and timer', async () => {
  let serverOpened = 0;
  let serverClosed = 0;
  let tunnelRef;

  const mock = await startMockServer({
    onUpgrade(req, socket, head, wss) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        serverOpened += 1;
        const idx = serverOpened;
        ws.on('close', () => {
          serverClosed += 1;
        });
        ws.once('message', () => {
          ws.send(
            JSON.stringify({
              ok: true,
              tunnel_id: `tid-rec-${idx}`,
              prefix: 'rec-race',
              public_url: 'http://rec-race.test.local',
              path_url: 'http://panel.test.local/t/rec-race/',
              preview_url: 'http://panel.test.local/preview/rec-race',
              dashboard_url: 'http://panel.test.local',
              error: null,
            }),
            () => {
              if (idx === 1) {
                setTimeout(() => ws.close(1012, 'drop'), 20);
              } else if (idx === 2 && tunnelRef) {
                // Fire concurrent close() calls right as reconnect RegisterResponse flushes
                void Promise.all([tunnelRef.close(), tunnelRef.close()]);
              }
            },
          );
        });
      });
    },
  });

  try {
    tunnelRef = await connect({
      url: 3000,
      server: `http://127.0.0.1:${mock.port}`,
      subdomain: 'rec-race',
      reconnectInitialDelayMs: 30,
      keepaliveIntervalMs: 50,
    });
    await tunnelRef.wait();
    assert.equal(tunnelRef.closed, true);

    const deadline = Date.now() + 2000;
    while (serverClosed < serverOpened && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(serverClosed, serverOpened, `leaked reconnect WS: opened=${serverOpened}, closed=${serverClosed}`);
  } finally {
    await tunnelRef?.close().catch(() => {});
    await mock.close();
  }
});
