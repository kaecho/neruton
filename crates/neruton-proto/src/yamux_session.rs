use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;

use futures_util::future::poll_fn;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[derive(Debug, Error)]
pub enum YamuxError {
    #[error("tunnel session closed")]
    Closed,
    #[error("yamux connection error: {0}")]
    Connection(#[from] yamux::ConnectionError),
}

/// Default Yamux configuration tuned for concurrent HTTP/WS proxying over WebSockets.
pub fn yamux_config() -> yamux::Config {
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(2048);
    cfg
}

type OpenStreamReply = oneshot::Sender<Result<yamux::Stream, YamuxError>>;

/// Server-side Yamux driver (`Mode::Client`): opens outbound streams to the connected tunnel CLI.
#[derive(Clone)]
pub struct YamuxClient {
    open_tx: mpsc::Sender<OpenStreamReply>,
    close_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    closed: Arc<AtomicBool>,
}

impl YamuxClient {
    /// Spawn a background Yamux client driver over an `AsyncRead + AsyncWrite` transport.
    /// Returns the cloneable handle and a `JoinHandle` that resolves when the session terminates.
    pub fn spawn<T>(io: T) -> (Self, JoinHandle<Result<(), yamux::ConnectionError>>)
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut conn = yamux::Connection::new(io.compat(), yamux_config(), yamux::Mode::Client);
        let (open_tx, mut open_rx) = mpsc::channel::<OpenStreamReply>(128);
        let (close_tx, mut close_rx) = oneshot::channel::<()>();
        let closed = Arc::new(AtomicBool::new(false));
        let closed_clone = closed.clone();

        let driver = tokio::spawn(async move {
            let mut pending_open: Option<OpenStreamReply> = None;
            let mut closing = false;

            let result = poll_fn(|cx| {
                if !closing && Pin::new(&mut close_rx).poll(cx).is_ready() {
                    closing = true;
                }

                if closing {
                    if let Some(reply) = pending_open.take() {
                        let _ = reply.send(Err(YamuxError::Closed));
                    }
                    return conn.poll_close(cx);
                }

                // Service outbound stream requests.
                loop {
                    if pending_open.is_none() {
                        match open_rx.poll_recv(cx) {
                            Poll::Ready(Some(reply)) => pending_open = Some(reply),
                            Poll::Ready(None) => {
                                closing = true;
                                return conn.poll_close(cx);
                            }
                            Poll::Pending => break,
                        }
                    }

                    if pending_open.is_some() {
                        match conn.poll_new_outbound(cx) {
                            Poll::Ready(Ok(stream)) => {
                                if let Some(reply) = pending_open.take() {
                                    let _ = reply.send(Ok(stream));
                                }
                            }
                            Poll::Ready(Err(err)) => {
                                if let Some(reply) = pending_open.take() {
                                    let _ = reply.send(Err(YamuxError::Closed));
                                }
                                return Poll::Ready(Err(err));
                            }
                            Poll::Pending => break,
                        }
                    }
                }

                // Drive the Yamux state machine (reads frames, ACKs, window updates, and closes).
                loop {
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(Some(Ok(_unexpected_inbound))) => {
                            // Server only opens outbound streams; ignore client-initiated streams.
                        }
                        Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                        Poll::Ready(None) => return Poll::Ready(Ok(())),
                        Poll::Pending => break,
                    }
                }

                Poll::Pending
            })
            .await;

            closed_clone.store(true, Ordering::SeqCst);
            if let Some(reply) = pending_open.take() {
                let _ = reply.send(Err(YamuxError::Closed));
            }
            while let Ok(reply) = open_rx.try_recv() {
                let _ = reply.send(Err(YamuxError::Closed));
            }
            result
        });

        (
            Self {
                open_tx,
                close_tx: Arc::new(Mutex::new(Some(close_tx))),
                closed,
            },
            driver,
        )
    }

    /// Open a new outbound Yamux stream to the remote tunnel client.
    pub async fn open_stream(&self) -> Result<yamux::Stream, YamuxError> {
        if self.is_closed() {
            return Err(YamuxError::Closed);
        }
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .await
            .map_err(|_| YamuxError::Closed)?;
        rx.await.map_err(|_| YamuxError::Closed)?
    }

    /// Signal the Yamux session to close.
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = self.close_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(());
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// CLI-side Yamux driver (`Mode::Server`): accepts inbound streams opened by `neruton-server`.
pub struct YamuxServer {
    inbound_rx: mpsc::UnboundedReceiver<yamux::Stream>,
    close_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    driver: JoinHandle<Result<(), yamux::ConnectionError>>,
}

impl YamuxServer {
    pub fn spawn<T>(io: T) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut conn = yamux::Connection::new(io.compat(), yamux_config(), yamux::Mode::Server);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let (close_tx, mut close_rx) = oneshot::channel::<()>();

        let driver = tokio::spawn(async move {
            let mut closing = false;
            poll_fn(|cx| {
                if !closing && Pin::new(&mut close_rx).poll(cx).is_ready() {
                    closing = true;
                }

                if closing {
                    return conn.poll_close(cx);
                }

                loop {
                    match conn.poll_next_inbound(cx) {
                        Poll::Ready(Some(Ok(stream))) => {
                            if inbound_tx.send(stream).is_err() {
                                closing = true;
                                return conn.poll_close(cx);
                            }
                        }
                        Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err)),
                        Poll::Ready(None) => return Poll::Ready(Ok(())),
                        Poll::Pending => break,
                    }
                }

                Poll::Pending
            })
            .await
        });

        Self {
            inbound_rx,
            close_tx: Arc::new(Mutex::new(Some(close_tx))),
            driver,
        }
    }

    /// Receive the next inbound stream opened by the server. Returns `None` when disconnected.
    pub async fn accept(&mut self) -> Option<yamux::Stream> {
        self.inbound_rx.recv().await
    }

    /// Gracefully signal the Yamux connection to close.
    pub fn close(&self) {
        if let Ok(mut guard) = self.close_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(());
            }
        }
    }

    /// Wait for the underlying Yamux driver task to finish.
    pub async fn wait_closed(self) -> Result<(), yamux::ConnectionError> {
        match self.driver.await {
            Ok(res) => res,
            Err(_) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::compat::FuturesAsyncReadCompatExt;

    #[tokio::test]
    async fn yamux_client_and_server_roundtrip() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let (client, client_task) = YamuxClient::spawn(a);
        let mut server = YamuxServer::spawn(b);

        let echo_task = tokio::spawn(async move {
            while let Some(stream) = server.accept().await {
                tokio::spawn(async move {
                    let mut io = stream.compat();
                    let mut buf = vec![0u8; 1024];
                    if let Ok(n) = io.read(&mut buf).await {
                        let _ = io.write_all(&buf[..n]).await;
                        let _ = io.shutdown().await;
                    }
                });
            }
        });

        let mut s = client.open_stream().await.unwrap().compat();
        s.write_all(b"hello yamux").await.unwrap();
        s.shutdown().await.unwrap();
        let mut reply = Vec::new();
        s.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"hello yamux");

        client.close();
        let _ = client_task.await;
        let _ = echo_task.await;
    }
}
