import { Duplex } from 'node:stream';
import WebSocket, { type RawData } from 'ws';

/** Maximum binary WebSocket frame payload size (matches Rust `WsByteStream`). */
export const MAX_WS_BINARY_FRAME = 64 * 1024;

function rawDataToBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) {
    return data;
  }
  if (Array.isArray(data)) {
    return Buffer.concat(data);
  }
  return Buffer.from(data);
}

/**
 * Adapts a connected `ws.WebSocket` (post-handshake) into a Node.js `Duplex`
 * binary byte stream suitable for Yamux multiplexing over WebSocket binary frames.
 */
export class WsByteStream extends Duplex {
  private readonly ws: WebSocket;
  private readonly readQueue: Buffer[] = [];
  private readingPaused = false;
  private eof = false;
  private endedPushed = false;

  private readonly onMessageBound: (data: RawData, isBinary: boolean) => void;
  private readonly onCloseBound: () => void;
  private readonly onErrorBound: (err: Error) => void;

  constructor(ws: WebSocket, initialBinaryChunks: Buffer[] = []) {
    super({
      readableHighWaterMark: 128 * 1024,
      writableHighWaterMark: 128 * 1024,
      allowHalfOpen: false,
    });
    this.ws = ws;

    for (const chunk of initialBinaryChunks) {
      if (chunk.length > 0) {
        this.readQueue.push(chunk);
      }
    }

    this.onMessageBound = (data: RawData, isBinary: boolean) => {
      if (!isBinary) {
        // Ignore unexpected text frames once in binary Yamux mode (matches Rust WsByteStream).
        return;
      }
      const buf = rawDataToBuffer(data);
      if (buf.length === 0) {
        return;
      }
      this.readQueue.push(buf);
      this.drainReadQueue();
    };

    this.onCloseBound = () => {
      this.eof = true;
      this.drainReadQueue();
    };

    this.onErrorBound = (err: Error) => {
      this.eof = true;
      this.destroy(err);
    };

    this.ws.on('message', this.onMessageBound);
    this.ws.on('close', this.onCloseBound);
    this.ws.on('error', this.onErrorBound);

    if (this.ws.readyState === WebSocket.CLOSING || this.ws.readyState === WebSocket.CLOSED) {
      this.eof = true;
    }
  }

  private detachListeners(): void {
    this.ws.off('message', this.onMessageBound);
    this.ws.off('close', this.onCloseBound);
    this.ws.off('error', this.onErrorBound);
  }

  private drainReadQueue(): void {
    while (!this.readingPaused && this.readQueue.length > 0) {
      const chunk = this.readQueue.shift()!;
      const ok = this.push(chunk);
      if (!ok) {
        this.readingPaused = true;
        return;
      }
    }
    if (this.eof && this.readQueue.length === 0 && !this.endedPushed) {
      this.endedPushed = true;
      this.push(null);
    }
  }

  override _read(_size: number): void {
    this.readingPaused = false;
    this.drainReadQueue();
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    if (buf.length === 0) {
      callback();
      return;
    }
    if (this.ws.readyState !== WebSocket.OPEN) {
      callback(new Error('WebSocket is not open'));
      return;
    }

    let offset = 0;
    const sendNext = (): void => {
      if (this.ws.readyState !== WebSocket.OPEN) {
        callback(new Error('WebSocket closed during write'));
        return;
      }
      const end = Math.min(offset + MAX_WS_BINARY_FRAME, buf.length);
      const slice = buf.subarray(offset, end);
      offset = end;
      const isLast = offset >= buf.length;

      this.ws.send(slice, { binary: true }, (err) => {
        if (err) {
          callback(err);
          return;
        }
        if (isLast) {
          callback();
        } else {
          sendNext();
        }
      });
    };

    sendNext();
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.close(1000);
      } catch {
        // Ignore close errors if already closing.
      }
    }
    callback();
  }

  override _destroy(err: Error | null, callback: (error?: Error | null) => void): void {
    this.detachListeners();
    this.readQueue.length = 0;
    this.eof = true;
    if (
      this.ws.readyState === WebSocket.OPEN ||
      this.ws.readyState === WebSocket.CONNECTING
    ) {
      try {
        if (err) {
          this.ws.terminate();
        } else {
          this.ws.close(1000);
        }
      } catch {
        // Ignore close errors.
      }
    }
    callback(err);
  }
}
