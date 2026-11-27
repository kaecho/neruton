import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { Duplex } from 'node:stream';
import { HOP_BY_HOP_HEADERS } from './constants.js';
import { NerutonError } from './errors.js';
import type { YamuxStream } from './yamux.js';

export type HostHeaderMode =
  | { type: 'rewrite' }
  | { type: 'preserve' }
  | { type: 'custom'; value: string };

export interface TargetConfig {
  url: URL;
  isHttps: boolean;
  connectHost: string;
  port: number;
  defaultHostHeader: string;
  basePath: string;
  hostHeaderMode: HostHeaderMode;
  noTlsVerify: boolean;
}

export interface ForwardedRequestEvent {
  method: string;
  path: string;
  status: number;
  durationMs: number;
  isWebSocket: boolean;
}

export function parseHostHeaderMode(raw?: string | null): HostHeaderMode {
  if (!raw) {
    return { type: 'rewrite' };
  }
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed.toLowerCase() === 'rewrite') {
    return { type: 'rewrite' };
  }
  if (trimmed.toLowerCase() === 'preserve') {
    return { type: 'preserve' };
  }
  return { type: 'custom', value: trimmed };
}

export function createTargetConfig(
  url: URL,
  opts: { hostHeader?: string | null; noTlsVerify?: boolean } = {},
): TargetConfig {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new NerutonError(
      `unsupported target scheme '${url.protocol}' (expected http: or https:)`,
      'INVALID_TARGET',
    );
  }
  const isHttps = url.protocol === 'https:';
  const rawHostname = url.hostname;
  if (!rawHostname) {
    throw new NerutonError('target URL is missing a host', 'INVALID_TARGET');
  }
  const connectHost = rawHostname.replace(/^\[|\]$/g, '');
  const port = url.port ? Number(url.port) : isHttps ? 443 : 80;
  const defaultHostHeader = url.port ? `${rawHostname}:${url.port}` : rawHostname;
  const basePath = url.pathname.replace(/\/+$/, '');

  return {
    url,
    isHttps,
    connectHost,
    port,
    defaultHostHeader,
    basePath,
    hostHeaderMode: parseHostHeaderMode(opts.hostHeader),
    noTlsVerify: Boolean(opts.noTlsVerify),
  };
}

function isHopByHop(lowerName: string, preserveUpgrade: boolean): boolean {
  if (preserveUpgrade && (lowerName === 'connection' || lowerName === 'upgrade')) {
    return false;
  }
  return HOP_BY_HOP_HEADERS.has(lowerName);
}

function isUpgradeHeaders(headers: http.IncomingHttpHeaders): boolean {
  const hasUpgrade = typeof headers.upgrade === 'string' && headers.upgrade.trim().length > 0;
  if (!hasUpgrade) return false;
  const conn = headers.connection;
  if (!conn) return false;
  const values: string[] = Array.isArray(conn) ? conn : [conn];
  return values.some((v: string) =>
    v.split(',').some((part: string) => part.trim().toLowerCase() === 'upgrade'),
  );
}

function isWebSocketUpgradeHeaders(headers: http.IncomingHttpHeaders): boolean {
  if (!isUpgradeHeaders(headers)) return false;
  return typeof headers.upgrade === 'string' && headers.upgrade.trim().toLowerCase() === 'websocket';
}

function buildForwardPath(basePath: string, origPath: string): string {
  const safeOrig = origPath && origPath.length > 0 ? origPath : '/';
  if (!basePath) {
    return safeOrig;
  }
  if (safeOrig.startsWith('/')) {
    return `${basePath}${safeOrig}`;
  }
  return `${basePath}/${safeOrig}`;
}

function buildOutgoingHeaders(
  rawHeaders: string[],
  target: TargetConfig,
  preserveUpgrade: boolean,
): http.OutgoingHttpHeaders {
  const out: http.OutgoingHttpHeaders = {};

  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = rawHeaders[i];
    const value = rawHeaders[i + 1];
    const lower = name.toLowerCase();

    if (isHopByHop(lower, preserveUpgrade)) {
      continue;
    }

    if (lower === 'host') {
      if (target.hostHeaderMode.type === 'preserve') {
        out.host = value;
      }
      continue;
    }

    const existing = out[lower];
    if (existing === undefined) {
      out[lower] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      out[lower] = [String(existing), value];
    }
  }

  if (target.hostHeaderMode.type === 'rewrite') {
    out.host = target.defaultHostHeader;
  } else if (target.hostHeaderMode.type === 'custom') {
    out.host = target.hostHeaderMode.value;
  }

  return out;
}

function buildFilteredResponseHeaders(
  rawHeaders: string[],
  preserveAll: boolean,
): http.OutgoingHttpHeaders {
  const out: http.OutgoingHttpHeaders = {};
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = rawHeaders[i];
    const value = rawHeaders[i + 1];
    const lower = name.toLowerCase();
    if (!preserveAll && isHopByHop(lower, false)) {
      continue;
    }
    const existing = out[lower];
    if (existing === undefined) {
      out[lower] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      out[lower] = [String(existing), value];
    }
  }
  return out;
}

function serializeRawResponseHead(
  statusCode: number,
  statusMessage: string,
  rawHeaders: string[],
  extraHeaders: Array<[string, string]> = [],
  stripHopByHop = false,
): string {
  const lines: string[] = [`HTTP/1.1 ${statusCode} ${statusMessage}`];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = rawHeaders[i];
    const value = rawHeaders[i + 1];
    if (stripHopByHop && isHopByHop(name.toLowerCase(), false)) {
      continue;
    }
    lines.push(`${name}: ${value}`);
  }
  for (const [k, v] of extraHeaders) {
    lines.push(`${k}: ${v}`);
  }
  lines.push('', '');
  return lines.join('\r\n');
}

function writeRawPlainError(socket: Duplex, statusCode: number, statusText: string, message: string): void {
  if (socket.destroyed || !socket.writable) {
    return;
  }
  const body = Buffer.from(message, 'utf8');
  const head = [
    `HTTP/1.1 ${statusCode} ${statusText}`,
    'Content-Type: text/plain; charset=utf-8',
    `Content-Length: ${body.length}`,
    'Connection: close',
    '',
    '',
  ].join('\r\n');
  socket.write(head);
  socket.end(body);
}

interface HttpCompatSocket extends Duplex {
  remoteAddress?: string;
  remoteFamily?: string;
  remotePort?: number;
  localAddress?: string;
  localPort?: number;
  _nerutonClosing?: boolean;
  setTimeout?: (timeout: number, callback?: () => void) => this;
  setNoDelay?: (noDelay?: boolean) => this;
  setKeepAlive?: (enable?: boolean, initialDelay?: number) => this;
  destroySoon?: () => void;
  ref?: () => this;
  unref?: () => this;
}

function makeHttpSocketCompat(stream: YamuxStream): HttpCompatSocket {
  const sock = stream as unknown as HttpCompatSocket;
  sock.remoteAddress = '127.0.0.1';
  sock.remoteFamily = 'IPv4';
  sock.remotePort = 0;
  sock.localAddress = '127.0.0.1';
  sock.localPort = 0;

  let timeoutHandle: NodeJS.Timeout | undefined;
  sock.setTimeout = function setTimeoutShim(msecs: number, cb?: () => void) {
    if (timeoutHandle) {
      clearTimeout(timeoutHandle);
      timeoutHandle = undefined;
    }
    if (cb) {
      sock.once('timeout', cb);
    }
    if (msecs > 0 && Number.isFinite(msecs)) {
      timeoutHandle = setTimeout(() => {
        sock.emit('timeout');
      }, msecs);
      timeoutHandle.unref?.();
      sock.once('close', () => {
        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
          timeoutHandle = undefined;
        }
      });
    }
    return sock;
  };
  sock.setNoDelay = function setNoDelayShim() {
    return sock;
  };
  sock.setKeepAlive = function setKeepAliveShim() {
    return sock;
  };
  sock.destroySoon = function destroySoonShim() {
    if (!sock.writableEnded) {
      sock.end();
    }
  };
  sock.ref = function refShim() {
    return sock;
  };
  sock.unref = function unrefShim() {
    return sock;
  };
  return sock;
}

/**
 * Forwards inbound HTTP/1.1 and WebSocket Yamux streams to a local HTTP/HTTPS service,
 * matching `crates/neruton-cli/src/forwarder.rs`.
 */
export class LocalForwarder {
  readonly target: TargetConfig;
  private readonly onRequestCallback?: (event: ForwardedRequestEvent) => void;
  private readonly server: http.Server;

  constructor(
    target: TargetConfig,
    onRequest?: (event: ForwardedRequestEvent) => void,
  ) {
    this.target = target;
    this.onRequestCallback = onRequest;

    this.server = http.createServer({
      keepAlive: false,
      noDelay: false,
      requestTimeout: 0,
      headersTimeout: 60_000,
    });

    this.server.on('request', (req, res) => {
      const sock = req.socket as unknown as HttpCompatSocket | null;
      if (sock?._nerutonClosing) {
        sock.destroy();
        return;
      }
      this.handleHttpRequest(req, res);
    });

    this.server.on('upgrade', (req, socket, head) => {
      const sock = socket as unknown as HttpCompatSocket;
      if (sock._nerutonClosing) {
        sock.destroy();
        return;
      }
      this.handleUpgradeRequest(req, socket as Duplex, head);
    });

    this.server.on('clientError', (_err, socket) => {
      const sock = socket as unknown as HttpCompatSocket;
      if (sock._nerutonClosing || socket.destroyed || socket.writableEnded) {
        // Early-response close is already managed by res 'finish'; do not truncate the
        // in-flight response body or append a trailing 400.
        return;
      }
      if (socket.writable) {
        socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      }
    });
  }

  /**
   * Attach an inbound `YamuxStream` to the local HTTP/1.1 + Upgrade forwarder.
   */
  handleStream(stream: YamuxStream): void {
    // Prevent unhandled stream errors from crashing the process when peers reset abruptly.
    stream.on('error', () => {});
    const compatSocket = makeHttpSocketCompat(stream);
    this.server.emit('connection', compatSocket);
  }

  private emitRequest(event: ForwardedRequestEvent): void {
    if (this.onRequestCallback) {
      try {
        this.onRequestCallback(event);
      } catch {
        // Ignore user callback errors.
      }
    }
  }

  private createUpstreamRequest(
    method: string,
    forwardPath: string,
    headers: http.OutgoingHttpHeaders,
  ): http.ClientRequest {
    const commonOpts: http.RequestOptions = {
      hostname: this.target.connectHost,
      port: this.target.port,
      method,
      path: forwardPath,
      headers,
      agent: false,
      setHost: false,
    };

    if (this.target.isHttps) {
      const tlsOpts: https.RequestOptions = {
        ...commonOpts,
        rejectUnauthorized: !this.target.noTlsVerify,
      };
      if (net.isIP(this.target.connectHost) === 0) {
        tlsOpts.servername = this.target.connectHost;
      }
      return https.request(tlsOpts);
    }
    return http.request(commonOpts);
  }

  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    const startedAt = Date.now();
    const origPath = req.url || '/';
    const method = req.method || 'GET';
    const forwardPath = buildForwardPath(this.target.basePath, origPath);
    const outHeaders = buildOutgoingHeaders(req.rawHeaders, this.target, false);

    let finished = false;
    let proxyResStarted = false;
    let proxyReq: http.ClientRequest;
    try {
      proxyReq = this.createUpstreamRequest(method, forwardPath, outHeaders);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const durationMs = Math.max(0, Date.now() - startedAt);
      this.emitRequest({ method, path: origPath, status: 502, durationMs, isWebSocket: false });
      const body = Buffer.from(
        `neruton: failed to connect to local service ${this.target.url.toString()}: ${msg}`,
        'utf8',
      );
      res.writeHead(502, 'Bad Gateway', {
        'content-type': 'text/plain; charset=utf-8',
        'content-length': String(body.length),
      });
      res.end(body);
      return;
    }

    proxyReq.on('response', (proxyRes) => {
      proxyResStarted = true;
      const status = proxyRes.statusCode ?? 502;
      const durationMs = Math.max(0, Date.now() - startedAt);
      this.emitRequest({
        method,
        path: origPath,
        status,
        durationMs,
        isWebSocket: false,
      });

      const respHeaders = buildFilteredResponseHeaders(proxyRes.rawHeaders, false);

      // RFC 9112 §9.6: If the backend responded before the client finished sending
      // the request body (e.g. early 413/401), force Connection: close, stop forwarding
      // unread body bytes, and close the stream after the response finishes so llhttp
      // never parses unread body bytes as a second request or emits a trailing 400.
      const earlyResponse = !req.complete;
      const clientSock = req.socket as unknown as HttpCompatSocket | null;
      if (earlyResponse) {
        respHeaders.connection = 'close';
        res.shouldKeepAlive = false;
        req.unpipe(proxyReq);
        req.pause();
        if (clientSock) {
          clientSock._nerutonClosing = true;
        }
      }

      res.writeHead(status, proxyRes.statusMessage, respHeaders);
      res.flushHeaders();

      const finishEarlyClose = (): void => {
        if (earlyResponse && clientSock && !clientSock.destroyed) {
          clientSock.pause();
          if (!clientSock.writableEnded) {
            clientSock.end();
          }
        }
      };

      if (method === 'HEAD' || status === 204 || status === 304) {
        finished = true;
        proxyRes.resume();
        res.end(finishEarlyClose);
        return;
      }

      proxyRes.on('error', (err) => {
        finished = true;
        if (!res.writableEnded) {
          res.destroy(err);
        }
      });

      res.on('finish', () => {
        finished = true;
        finishEarlyClose();
      });

      proxyRes.pipe(res);
    });

    proxyReq.on('error', (err) => {
      if (finished) {
        return;
      }
      if (proxyResStarted) {
        // Backend may reset/close the request-write half after sending an early response
        // (e.g. 413); let proxyRes deliver the response body cleanly.
        return;
      }
      finished = true;
      const durationMs = Math.max(0, Date.now() - startedAt);
      if (!res.headersSent) {
        this.emitRequest({
          method,
          path: origPath,
          status: 502,
          durationMs,
          isWebSocket: false,
        });
        const msg = `neruton: failed to connect to local service ${this.target.url.toString()}: ${err.message}`;
        const body = Buffer.from(msg, 'utf8');
        res.writeHead(502, 'Bad Gateway', {
          'content-type': 'text/plain; charset=utf-8',
          'content-length': String(body.length),
        });
        res.end(body);
      } else if (!res.destroyed) {
        res.destroy(err);
      }
    });

    req.on('error', () => {
      if (!finished) {
        proxyReq.destroy();
      }
    });

    res.on('close', () => {
      if (!finished && !res.writableFinished) {
        proxyReq.destroy();
      }
    });

    req.pipe(proxyReq);
  }

  private handleUpgradeRequest(
    req: http.IncomingMessage,
    clientSocket: Duplex,
    head: Buffer,
  ): void {
    const startedAt = Date.now();
    const origPath = req.url || '/';
    const method = req.method || 'GET';
    const isWs = isWebSocketUpgradeHeaders(req.headers);
    const logMethod = isWs ? 'WS' : method;
    const forwardPath = buildForwardPath(this.target.basePath, origPath);
    const outHeaders = buildOutgoingHeaders(req.rawHeaders, this.target, true);

    let settled = false;
    let proxyReq: http.ClientRequest;
    try {
      proxyReq = this.createUpstreamRequest(method, forwardPath, outHeaders);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const durationMs = Math.max(0, Date.now() - startedAt);
      this.emitRequest({ method: logMethod, path: origPath, status: 502, durationMs, isWebSocket: isWs });
      writeRawPlainError(
        clientSocket,
        502,
        'Bad Gateway',
        `neruton: failed to connect to local service ${this.target.url.toString()}: ${msg}`,
      );
      return;
    }

    proxyReq.on('upgrade', (proxyRes, proxySocket, proxyHead) => {
      if (settled) {
        proxySocket.destroy();
        return;
      }
      settled = true;

      const status = proxyRes.statusCode ?? 101;
      const durationMs = Math.max(0, Date.now() - startedAt);
      this.emitRequest({
        method: logMethod,
        path: origPath,
        status,
        durationMs,
        isWebSocket: isWs,
      });

      const rawHead = serializeRawResponseHead(
        status,
        proxyRes.statusMessage || 'Switching Protocols',
        proxyRes.rawHeaders,
        [],
        false,
      );
      clientSocket.write(rawHead);

      if (proxyHead && proxyHead.length > 0) {
        clientSocket.write(proxyHead);
      }
      if (head && head.length > 0) {
        proxySocket.write(head);
      }

      const cleanupBoth = (): void => {
        if (!clientSocket.destroyed) {
          clientSocket.destroy();
        }
        if (!proxySocket.destroyed) {
          proxySocket.destroy();
        }
      };

      proxySocket.on('error', cleanupBoth);
      clientSocket.on('error', cleanupBoth);
      proxySocket.on('close', (hadError) => {
        if (hadError) {
          if (!clientSocket.destroyed) {
            clientSocket.destroy();
          }
        } else if (!clientSocket.destroyed && !clientSocket.writableEnded) {
          // Propagate clean EOF only via .end() so any bytes queued behind Yamux flow control
          // finish draining and emit FIN instead of being truncated by RST.
          clientSocket.end();
        }
      });
      clientSocket.on('close', () => {
        if (!proxySocket.destroyed) {
          if (!proxySocket.writableEnded) {
            proxySocket.end();
          }
          if (proxySocket.writableFinished) {
            proxySocket.destroy();
          } else {
            proxySocket.once('finish', () => {
              if (!proxySocket.destroyed) {
                proxySocket.destroy();
              }
            });
          }
        }
      });

      proxySocket.pipe(clientSocket);
      clientSocket.pipe(proxySocket);
    });

    proxyReq.on('response', (proxyRes) => {
      if (settled) {
        proxyRes.resume();
        return;
      }
      settled = true;

      const status = proxyRes.statusCode ?? 502;
      const durationMs = Math.max(0, Date.now() - startedAt);
      this.emitRequest({
        method: logMethod,
        path: origPath,
        status,
        durationMs,
        isWebSocket: isWs,
      });

      const hasContentLength = proxyRes.headers['content-length'] !== undefined;
      const isBodyless = method === 'HEAD' || status === 204 || status === 304;
      const extraHeaders: Array<[string, string]> = [['Connection', 'close']];
      const useChunked = !hasContentLength && !isBodyless;
      if (useChunked) {
        extraHeaders.push(['Transfer-Encoding', 'chunked']);
      }

      const rawHead = serializeRawResponseHead(
        status,
        proxyRes.statusMessage || http.STATUS_CODES[status] || '',
        proxyRes.rawHeaders,
        extraHeaders,
        true,
      );
      clientSocket.write(rawHead);

      if (isBodyless) {
        proxyRes.resume();
        clientSocket.end();
        return;
      }

      if (useChunked) {
        proxyRes.on('data', (chunk: Buffer) => {
          if (chunk.length > 0 && !clientSocket.destroyed && clientSocket.writable) {
            clientSocket.write(`${chunk.length.toString(16)}\r\n`);
            clientSocket.write(chunk);
            clientSocket.write('\r\n');
          }
        });
        proxyRes.on('end', () => {
          if (!clientSocket.destroyed && clientSocket.writable) {
            clientSocket.end('0\r\n\r\n');
          }
        });
      } else {
        proxyRes.pipe(clientSocket);
      }

      proxyRes.on('error', () => {
        if (!clientSocket.destroyed) {
          clientSocket.destroy();
        }
      });
    });

    proxyReq.on('error', (err) => {
      if (settled) {
        return;
      }
      settled = true;
      const durationMs = Math.max(0, Date.now() - startedAt);
      this.emitRequest({
        method: logMethod,
        path: origPath,
        status: 502,
        durationMs,
        isWebSocket: isWs,
      });
      writeRawPlainError(
        clientSocket,
        502,
        'Bad Gateway',
        `neruton: failed to connect to local service ${this.target.url.toString()}: ${err.message}`,
      );
    });

    clientSocket.on('close', () => {
      if (!settled) {
        proxyReq.destroy();
      }
    });

    proxyReq.end();
  }
}
