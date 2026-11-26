use std::collections::VecDeque;
use std::fmt::Display;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::{Buf, Bytes, BytesMut};
use futures_util::{ready, Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

const MAX_WS_BINARY_FRAME: usize = 64 * 1024;

/// Decoded WebSocket frame kind abstracted across `axum::extract::ws::Message`
/// and `tokio_tungstenite::tungstenite::Message`.
pub enum WsFrameKind {
    Binary(Bytes),
    Text(String),
    Ping(Bytes),
    Pong(Bytes),
    Close,
}

/// Trait allowing `WsByteStream` to adapt any WebSocket message type into an
/// `AsyncRead + AsyncWrite` binary stream for Yamux multiplexing.
pub trait WsFrame: Sized + Unpin + Send + 'static {
    fn binary(data: Bytes) -> Self;
    fn ping(data: Bytes) -> Self;
    fn into_kind(self) -> WsFrameKind;
}

impl WsFrame for tokio_tungstenite::tungstenite::Message {
    fn binary(data: Bytes) -> Self {
        tokio_tungstenite::tungstenite::Message::Binary(data)
    }

    fn ping(data: Bytes) -> Self {
        tokio_tungstenite::tungstenite::Message::Ping(data)
    }

    fn into_kind(self) -> WsFrameKind {
        match self {
            tokio_tungstenite::tungstenite::Message::Binary(b) => WsFrameKind::Binary(b),
            tokio_tungstenite::tungstenite::Message::Text(t) => WsFrameKind::Text(t.to_string()),
            tokio_tungstenite::tungstenite::Message::Ping(p) => WsFrameKind::Ping(p),
            tokio_tungstenite::tungstenite::Message::Pong(p) => WsFrameKind::Pong(p),
            tokio_tungstenite::tungstenite::Message::Close(_) => WsFrameKind::Close,
            tokio_tungstenite::tungstenite::Message::Frame(_) => WsFrameKind::Binary(Bytes::new()),
        }
    }
}

/// Optional heartbeat ping/RTT latency tracker attached to a `WsByteStream`.
pub struct WsPingTracker {
    pub ping_rx: mpsc::Receiver<Bytes>,
    pub latency_ms: Arc<AtomicU64>,
    pub epoch: Instant,
}

/// Wraps a WebSocket `Stream + Sink` into a `tokio::io::AsyncRead + AsyncWrite` byte stream
/// over WebSocket binary frames, enabling Yamux multiplexing over standard `wss://` (port 443).
pub struct WsByteStream<S, M> {
    inner: S,
    read_buf: BytesMut,
    pending_ctrl: VecDeque<M>,
    needs_ctrl_flush: bool,
    ping_tracker: Option<WsPingTracker>,
    eof: bool,
    _marker: PhantomData<M>,
}

impl<S, M> Unpin for WsByteStream<S, M> where S: Unpin {}

impl<S, M> WsByteStream<S, M> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
            pending_ctrl: VecDeque::new(),
            needs_ctrl_flush: false,
            ping_tracker: None,
            eof: false,
            _marker: PhantomData,
        }
    }

    pub fn with_ping_tracker(inner: S, tracker: WsPingTracker) -> Self {
        Self {
            inner,
            read_buf: BytesMut::new(),
            pending_ctrl: VecDeque::new(),
            needs_ctrl_flush: false,
            ping_tracker: Some(tracker),
            eof: false,
            _marker: PhantomData,
        }
    }
}

impl<S, M, E> WsByteStream<S, M>
where
    S: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WsFrame,
    E: Display,
{
    fn drain_ping_channel(&mut self, cx: &mut Context<'_>) {
        if let Some(tracker) = &mut self.ping_tracker {
            while self.pending_ctrl.len() < 4 {
                match tracker.ping_rx.poll_recv(cx) {
                    Poll::Ready(Some(payload)) => {
                        self.pending_ctrl.push_back(M::ping(payload));
                    }
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }
        }
    }

    fn poll_flush_ctrl(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.drain_ping_channel(cx);
        while !self.pending_ctrl.is_empty() {
            match self.inner.poll_ready_unpin(cx) {
                Poll::Ready(Ok(())) => {
                    if let Some(frame) = self.pending_ctrl.pop_front() {
                        self.inner.start_send_unpin(frame).map_err(|e| {
                            io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())
                        })?;
                        self.needs_ctrl_flush = true;
                    }
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.needs_ctrl_flush {
            match self.inner.poll_flush_unpin(cx) {
                Poll::Ready(Ok(())) => self.needs_ctrl_flush = false,
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    fn record_pong(&self, payload: &[u8]) {
        if payload.len() == 8 {
            if let Some(tracker) = &self.ping_tracker {
                let sent_us = u64::from_be_bytes(payload.try_into().unwrap_or([0; 8]));
                let now_us = tracker.epoch.elapsed().as_micros() as u64;
                let rtt_us = now_us.saturating_sub(sent_us);
                let rtt_ms = rtt_us.div_ceil(1000).max(if rtt_us > 0 { 1 } else { 0 });
                tracker.latency_ms.store(rtt_ms, Ordering::Relaxed);
            }
        }
    }
}

impl<S, M, E> AsyncRead for WsByteStream<S, M>
where
    S: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WsFrame,
    E: Display,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;

        // Best-effort send any queued keepalive ping frames without blocking reads.
        let _ = this.poll_flush_ctrl(cx);

        if !this.read_buf.is_empty() {
            let to_copy = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..to_copy]);
            this.read_buf.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        if this.eof {
            return Poll::Ready(Ok(()));
        }

        loop {
            match this.inner.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    this.eof = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )));
                }
                Poll::Ready(Some(Ok(msg))) => match msg.into_kind() {
                    WsFrameKind::Binary(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        if data.len() <= buf.remaining() {
                            buf.put_slice(&data);
                        } else {
                            let n = buf.remaining();
                            buf.put_slice(&data[..n]);
                            this.read_buf.extend_from_slice(&data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    WsFrameKind::Ping(_) => {
                        // Underlying tungstenite automatically queues the matching Pong;
                        // ensure the sink is flushed even when no Yamux data is being written.
                        this.needs_ctrl_flush = true;
                        let _ = this.poll_flush_ctrl(cx);
                    }
                    WsFrameKind::Pong(payload) => {
                        this.record_pong(&payload);
                    }
                    WsFrameKind::Close => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    WsFrameKind::Text(_) => {
                        // Ignore unexpected text frames once in binary Yamux mode.
                    }
                },
            }
        }
    }
}

impl<S, M, E> AsyncWrite for WsByteStream<S, M>
where
    S: Stream<Item = Result<M, E>> + Sink<M, Error = E> + Unpin,
    M: WsFrame,
    E: Display,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        ready!(this.poll_flush_ctrl(cx))?;
        ready!(this
            .inner
            .poll_ready_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())))?;

        let chunk_len = buf.len().min(MAX_WS_BINARY_FRAME);
        let frame = M::binary(Bytes::copy_from_slice(&buf[..chunk_len]));
        this.inner
            .start_send_unpin(frame)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))?;

        Poll::Ready(Ok(chunk_len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_flush_ctrl(cx))?;
        this.inner
            .poll_flush_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.inner
            .poll_close_unpin(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string()))
    }
}
