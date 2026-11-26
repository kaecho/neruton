use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{HeaderMap, Request, StatusCode, Uri, Version};
use axum::response::{Html, IntoResponse, Response};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::BodyExt;
use hyper::body::{Body as HttpBody, Frame};
use hyper_util::rt::TokioIo;
use neruton_proto::RequestLog;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, warn};
use url::Url;
use uuid::Uuid;

use crate::html::{
    inject_base_tag, offline_page_html, rewrite_location_header, strip_csp_frame_ancestors,
};
use crate::state::{ActiveTunnel, AppState};

const MAX_HTML_REWRITE_BYTES: usize = 8 * 1024 * 1024;

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

struct StreamGuard {
    counter: Arc<ActiveTunnel>,
}

impl StreamGuard {
    fn new(tunnel: Arc<ActiveTunnel>) -> Self {
        tunnel.active_streams.fetch_add(1, Ordering::Relaxed);
        Self { counter: tunnel }
    }
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        self.counter.active_streams.fetch_sub(1, Ordering::Relaxed);
    }
}

struct CountingIo<T> {
    inner: T,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
}

impl<T> CountingIo<T> {
    fn new(inner: T, bytes_in: Arc<AtomicU64>, bytes_out: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            bytes_in,
            bytes_out,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountingIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let added = buf.filled().len().saturating_sub(before) as u64;
            if added > 0 {
                self.bytes_out.fetch_add(added, Ordering::Relaxed);
            }
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountingIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            if *n > 0 {
                self.bytes_in.fetch_add(*n as u64, Ordering::Relaxed);
            }
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct RequestLogMeta {
    state: Arc<AppState>,
    tunnel: Arc<ActiveTunnel>,
    started_at: Instant,
    method: String,
    path: String,
    host: String,
    via: &'static str,
    status: u16,
    client_ip: String,
    user_agent: String,
    bytes_in: Arc<AtomicU64>,
    bytes_out: Arc<AtomicU64>,
    _stream_guard: StreamGuard,
}

impl RequestLogMeta {
    fn record(self) {
        let log = RequestLog {
            id: Uuid::new_v4().to_string(),
            tunnel_prefix: self.tunnel.prefix.clone(),
            timestamp: Utc::now().to_rfc3339(),
            method: self.method,
            path: self.path,
            host: self.host,
            via: self.via.to_string(),
            status: self.status,
            duration_ms: self.started_at.elapsed().as_millis() as u64,
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            client_ip: self.client_ip,
            user_agent: self.user_agent,
        };
        self.state.record_request(&self.tunnel, log);
    }
}

struct TrackingResponseBody {
    inner: hyper::body::Incoming,
    meta: Option<RequestLogMeta>,
}

impl HttpBody for TrackingResponseBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let poll = Pin::new(&mut self.inner).poll_frame(cx);
        match &poll {
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                if let Some(meta) = self.meta.take() {
                    meta.record();
                }
            }
            Poll::Ready(Some(Ok(_))) => {
                if self.inner.is_end_stream() {
                    if let Some(meta) = self.meta.take() {
                        meta.record();
                    }
                }
            }
            Poll::Pending => {}
        }
        poll
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TrackingResponseBody {
    fn drop(&mut self) {
        if let Some(meta) = self.meta.take() {
            meta.record();
        }
    }
}

pub fn tunnel_offline_response(state: &AppState, prefix: &str) -> Response {
    let html = offline_page_html(
        prefix,
        &state.config.dashboard_url(),
        &state.config.base_domain(),
    );
    (StatusCode::BAD_GATEWAY, Html(html)).into_response()
}

fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let has_upgrade = headers.contains_key(header::UPGRADE);
    let has_conn_upgrade = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|s| {
            s.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        });
    has_upgrade && has_conn_upgrade
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    is_upgrade_request(headers)
        && headers
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
}

fn is_hop_by_hop(name: &HeaderName, preserve_upgrade: bool) -> bool {
    let lower = name.as_str().to_ascii_lowercase();
    if preserve_upgrade && (lower == "connection" || lower == "upgrade") {
        return false;
    }
    HOP_BY_HOP_HEADERS.contains(&lower.as_str())
}

fn append_forwarded_headers(
    headers: &mut HeaderMap,
    client_ip: &str,
    original_host: &str,
    public_scheme: &str,
) {
    if !client_ip.is_empty() && client_ip != "unknown" {
        let new_xff = match headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .filter(|s| !s.is_empty())
        {
            Some(existing) => format!("{existing}, {client_ip}"),
            None => client_ip.to_string(),
        };
        if let Ok(val) = HeaderValue::from_str(&new_xff) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), val);
        }
        if !headers.contains_key("x-real-ip") {
            if let Ok(val) = HeaderValue::from_str(client_ip) {
                headers.insert(HeaderName::from_static("x-real-ip"), val);
            }
        }
    }
    if !headers.contains_key("x-forwarded-host") && !original_host.is_empty() {
        if let Ok(val) = HeaderValue::from_str(original_host) {
            headers.insert(HeaderName::from_static("x-forwarded-host"), val);
        }
    }
    if !headers.contains_key("x-forwarded-proto") {
        if let Ok(val) = HeaderValue::from_str(public_scheme) {
            headers.insert(HeaderName::from_static("x-forwarded-proto"), val);
        }
    }
}

/// Forward an HTTP/1.1 or WebSocket request through an active tunnel's Yamux stream.
#[allow(clippy::too_many_arguments)]
pub async fn proxy_to_tunnel(
    state: Arc<AppState>,
    tunnel: Arc<ActiveTunnel>,
    mut req: Request<Body>,
    via: &'static str,
    target_path_and_query: String,
    client_ip: String,
    original_host: String,
    is_path_mode: bool,
) -> Response {
    let started_at = Instant::now();
    let stream_guard = StreamGuard::new(tunnel.clone());
    let is_head_req = req.method() == axum::http::Method::HEAD;
    let is_upgrade = is_upgrade_request(req.headers());
    let is_ws = is_websocket_upgrade(req.headers());
    let method_str = if is_ws {
        "WS".to_string()
    } else {
        req.method().to_string()
    };
    let user_agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let client_on_upgrade = if is_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let yamux_stream =
        match tokio::time::timeout(Duration::from_secs(15), tunnel.yamux.open_stream()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                warn!(prefix = %tunnel.prefix, error = %e, "failed to open yamux stream");
                return tunnel_offline_response(&state, &tunnel.prefix);
            }
            Err(_) => {
                warn!(prefix = %tunnel.prefix, "timed out opening yamux stream");
                return (
                    StatusCode::GATEWAY_TIMEOUT,
                    "Timed out opening tunnel stream",
                )
                    .into_response();
            }
        };

    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let io = TokioIo::new(CountingIo::new(
        yamux_stream.compat(),
        bytes_in.clone(),
        bytes_out.clone(),
    ));

    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            warn!(prefix = %tunnel.prefix, error = %e, "tunnel http1 handshake failed");
            return (
                StatusCode::BAD_GATEWAY,
                format!("Tunnel handshake error: {e}"),
            )
                .into_response();
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!("tunnel upstream connection closed: {e}");
        }
    });

    let target_uri: Uri = target_path_and_query
        .parse()
        .unwrap_or_else(|_| Uri::from_static("/"));

    let (parts, body) = req.into_parts();
    let mut out_req_builder = Request::builder()
        .method(parts.method)
        .uri(target_uri)
        .version(Version::HTTP_11);

    if let Some(headers) = out_req_builder.headers_mut() {
        for (name, value) in &parts.headers {
            if is_hop_by_hop(name, is_upgrade) {
                continue;
            }
            if is_path_mode && *name == header::ACCEPT_ENCODING {
                // Request uncompressed payloads on path proxy so HTML `<base>` injection works cleanly.
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        if !headers.contains_key(header::HOST) && !original_host.is_empty() {
            if let Ok(hv) = HeaderValue::from_str(&original_host) {
                headers.insert(header::HOST, hv);
            }
        }
        append_forwarded_headers(
            headers,
            &client_ip,
            &original_host,
            &state.config.public_scheme(),
        );
    }

    let out_req = match out_req_builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to build tunneled request: {e}"),
            )
                .into_response();
        }
    };

    let mut upstream_resp = match sender.send_request(out_req).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!(prefix = %tunnel.prefix, error = %e, "error forwarding request through tunnel");
            return (
                StatusCode::BAD_GATEWAY,
                format!("Tunnel upstream error: {e}"),
            )
                .into_response();
        }
    };

    let status = upstream_resp.status();

    // Handle 101 Switching Protocols (WebSocket & HTTP upgrades).
    if status == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_on_upgrade = hyper::upgrade::on(&mut upstream_resp);
        let log = RequestLog {
            id: Uuid::new_v4().to_string(),
            tunnel_prefix: tunnel.prefix.clone(),
            timestamp: Utc::now().to_rfc3339(),
            method: method_str,
            path: target_path_and_query,
            host: original_host,
            via: via.to_string(),
            status: status.as_u16(),
            duration_ms: started_at.elapsed().as_millis() as u64,
            bytes_in: bytes_in.load(Ordering::Relaxed),
            bytes_out: bytes_out.load(Ordering::Relaxed),
            client_ip,
            user_agent,
        };
        state.record_request(&tunnel, log);

        if let Some(client_upgrade) = client_on_upgrade {
            let tunnel_for_ws = tunnel.clone();
            tokio::spawn(async move {
                let _keep_stream_guard = stream_guard;
                match tokio::try_join!(client_upgrade, upstream_on_upgrade) {
                    Ok((client_upgraded, upstream_upgraded)) => {
                        let mut c = TokioIo::new(client_upgraded);
                        let mut u = TokioIo::new(upstream_upgraded);
                        match tokio::io::copy_bidirectional(&mut c, &mut u).await {
                            Ok((to_upstream, to_client)) => {
                                tunnel_for_ws
                                    .bytes_in
                                    .fetch_add(to_upstream, Ordering::Relaxed);
                                tunnel_for_ws
                                    .bytes_out
                                    .fetch_add(to_client, Ordering::Relaxed);
                            }
                            Err(e) => debug!("upgraded websocket tunnel closed: {e}"),
                        }
                    }
                    Err(e) => debug!("upgrade handshake failed: {e}"),
                }
            });
        }

        let (resp_parts, resp_body) = upstream_resp.into_parts();
        let mut resp_builder = Response::builder().status(resp_parts.status);
        if let Some(headers) = resp_builder.headers_mut() {
            for (name, value) in &resp_parts.headers {
                headers.append(name.clone(), value.clone());
            }
        }
        return resp_builder
            .body(Body::new(resp_body))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let (resp_parts, resp_body) = upstream_resp.into_parts();
    let mut out_headers = HeaderMap::new();
    for (name, value) in &resp_parts.headers {
        if is_hop_by_hop(name, false) {
            continue;
        }
        if is_path_mode {
            let lower = name.as_str().to_ascii_lowercase();
            if lower == "x-frame-options" {
                continue;
            }
            if lower == "content-security-policy" {
                if let Ok(csp_str) = value.to_str() {
                    if let Some(cleaned) = strip_csp_frame_ancestors(csp_str) {
                        if let Ok(hv) = HeaderValue::from_str(&cleaned) {
                            out_headers.append(name.clone(), hv);
                        }
                    }
                }
                continue;
            }
            if lower == "location" {
                if let Ok(loc) = value.to_str() {
                    if let Some(rewritten) = rewrite_location_header(loc, &tunnel.prefix) {
                        if let Ok(hv) = HeaderValue::from_str(&rewritten) {
                            out_headers.append(name.clone(), hv);
                            continue;
                        }
                    }
                }
            }
        }
        out_headers.append(name.clone(), value.clone());
    }

    let meta = RequestLogMeta {
        state: state.clone(),
        tunnel: tunnel.clone(),
        started_at,
        method: method_str,
        path: target_path_and_query,
        host: original_host,
        via,
        status: status.as_u16(),
        client_ip,
        user_agent,
        bytes_in: bytes_in.clone(),
        bytes_out: bytes_out.clone(),
        _stream_guard: stream_guard,
    };

    // In path mode, inject `<base href="/t/<prefix>/">` into uncompressed HTML responses
    // that actually carry a body.
    let has_response_body = !is_head_req
        && !status.is_informational()
        && status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED;
    let should_rewrite_html =
        is_path_mode && has_response_body && is_uncompressed_html(&out_headers);
    if should_rewrite_html {
        let content_len = out_headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        if content_len.is_none_or(|len| len <= MAX_HTML_REWRITE_BYTES) {
            match resp_body.collect().await {
                Ok(collected) => {
                    let raw_bytes = collected.to_bytes();
                    let html = String::from_utf8_lossy(&raw_bytes);
                    let rewritten = inject_base_tag(&html, &tunnel.prefix);
                    let final_bytes = Bytes::from(rewritten.into_bytes());
                    out_headers.remove(header::CONTENT_LENGTH);
                    if let Ok(hv) = HeaderValue::from_str(&final_bytes.len().to_string()) {
                        out_headers.insert(header::CONTENT_LENGTH, hv);
                    }
                    meta.record();
                    let mut resp_builder = Response::builder().status(status);
                    if let Some(h) = resp_builder.headers_mut() {
                        *h = out_headers;
                    }
                    return resp_builder
                        .body(Body::from(final_bytes))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
                }
                Err(e) => {
                    meta.record();
                    return (StatusCode::BAD_GATEWAY, format!("Failed reading body: {e}"))
                        .into_response();
                }
            }
        }
    }

    let tracked_body = TrackingResponseBody {
        inner: resp_body,
        meta: Some(meta),
    };
    let mut resp_builder = Response::builder().status(status);
    if let Some(h) = resp_builder.headers_mut() {
        *h = out_headers;
    }
    resp_builder
        .body(Body::new(tracked_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

fn is_uncompressed_html(headers: &HeaderMap) -> bool {
    let is_html = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false);
    if !is_html {
        return false;
    }
    match headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_ascii_lowercase())
    {
        None => true,
        Some(enc) => enc.is_empty() || enc == "identity",
    }
}

/// Reverse-proxy non-API/non-tunnel panel requests to `NERUTON_WEB_UPSTREAM` (Next.js),
/// supporting streaming responses and WebSocket upgrades.
pub async fn proxy_to_web_upstream(
    upstream_base: &str,
    mut req: Request<Body>,
    client_ip: String,
    original_host: String,
    public_scheme: &str,
) -> Response {
    let parsed = match Url::parse(upstream_base) {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("Invalid NERUTON_WEB_UPSTREAM '{upstream_base}': {e}"),
            )
                .into_response();
        }
    };

    let Some(host) = parsed.host_str() else {
        return (StatusCode::BAD_GATEWAY, "NERUTON_WEB_UPSTREAM missing host").into_response();
    };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let connect_addr = format!("{host}:{port}");

    let is_upgrade = is_upgrade_request(req.headers());
    let client_on_upgrade = if is_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let tcp = match TcpStream::connect(&connect_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(upstream = %connect_addr, error = %e, "failed to connect to web upstream");
            return (
                StatusCode::BAD_GATEWAY,
                format!("Web panel upstream unavailable ({connect_addr}): {e}"),
            )
                .into_response();
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tcp))
        .await
    {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("Web upstream handshake failed: {e}"),
            )
                .into_response();
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!("web upstream connection closed: {e}");
        }
    });

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let (parts, body) = req.into_parts();
    let mut out_builder = Request::builder()
        .method(parts.method)
        .uri(path_and_query)
        .version(Version::HTTP_11);

    let upstream_host_header = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };

    if let Some(headers) = out_builder.headers_mut() {
        for (name, value) in &parts.headers {
            if is_hop_by_hop(name, is_upgrade) || *name == header::HOST {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        if let Ok(hv) = HeaderValue::from_str(&upstream_host_header) {
            headers.insert(header::HOST, hv);
        }
        append_forwarded_headers(headers, &client_ip, &original_host, public_scheme);
    }

    let out_req = match out_builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed building upstream request: {e}"),
            )
                .into_response();
        }
    };

    let mut resp = match sender.send_request(out_req).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!("Web upstream request failed: {e}"),
            )
                .into_response();
        }
    };

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_on_upgrade = hyper::upgrade::on(&mut resp);
        if let Some(client_upgrade) = client_on_upgrade {
            tokio::spawn(async move {
                if let Ok((c, u)) = tokio::try_join!(client_upgrade, upstream_on_upgrade) {
                    let mut c = TokioIo::new(c);
                    let mut u = TokioIo::new(u);
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
                }
            });
        }
        let (resp_parts, resp_body) = resp.into_parts();
        let mut builder = Response::builder().status(resp_parts.status);
        if let Some(headers) = builder.headers_mut() {
            for (name, value) in &resp_parts.headers {
                headers.append(name.clone(), value.clone());
            }
        }
        return builder
            .body(Body::new(resp_body))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let (resp_parts, resp_body) = resp.into_parts();
    let mut builder = Response::builder().status(resp_parts.status);
    if let Some(headers) = builder.headers_mut() {
        for (name, value) in &resp_parts.headers {
            if is_hop_by_hop(name, false) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
    }
    builder
        .body(Body::new(resp_body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
