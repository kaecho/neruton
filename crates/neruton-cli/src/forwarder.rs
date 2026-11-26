use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Request, Response, StatusCode, Uri, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::debug;
use url::Url;

use crate::ui;

type ProxyBody = BoxBody<Bytes, hyper::Error>;

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

#[derive(Debug, Clone)]
pub enum HostHeaderMode {
    RewriteToTarget,
    Preserve,
    Custom(String),
}

impl HostHeaderMode {
    pub fn from_option(opt: Option<String>) -> Self {
        match opt {
            None => Self::RewriteToTarget,
            Some(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("rewrite") {
                    Self::RewriteToTarget
                } else if trimmed.eq_ignore_ascii_case("preserve") {
                    Self::Preserve
                } else {
                    Self::Custom(trimmed.to_string())
                }
            }
        }
    }
}

pub struct TargetConfig {
    pub url: Url,
    pub scheme_https: bool,
    pub host: String,
    pub port: u16,
    pub default_host_header: String,
    pub base_path: String,
    pub host_header_mode: HostHeaderMode,
    pub tls_config: Arc<rustls::ClientConfig>,
}

impl TargetConfig {
    pub fn new(
        url: Url,
        host_header_mode: HostHeaderMode,
        tls_config: Arc<rustls::ClientConfig>,
    ) -> anyhow::Result<Self> {
        let scheme_https = match url.scheme() {
            "https" => true,
            "http" => false,
            other => anyhow::bail!("unsupported target scheme '{other}' (expected http or https)"),
        };
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("target URL is missing a host"))?
            .to_string();
        let port = url
            .port_or_known_default()
            .unwrap_or(if scheme_https { 443 } else { 80 });

        let default_host_header = match url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };

        let base_path = url.path().trim_end_matches('/').to_string();

        Ok(Self {
            url,
            scheme_https,
            host,
            port,
            default_host_header,
            base_path,
            host_header_mode,
            tls_config,
        })
    }
}

enum TargetStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for TargetStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            TargetStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            TargetStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TargetStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            TargetStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            TargetStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            TargetStream::Plain(s) => Pin::new(s).poll_flush(cx),
            TargetStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match &mut *self {
            TargetStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            TargetStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

async fn connect_target(target: &TargetConfig) -> anyhow::Result<TargetStream> {
    let addr = format!("{}:{}", target.host, target.port);
    let tcp = TcpStream::connect(&addr).await?;
    let _ = tcp.set_nodelay(true);

    if !target.scheme_https {
        return Ok(TargetStream::Plain(tcp));
    }

    let connector = TlsConnector::from(target.tls_config.clone());
    let server_name = ServerName::try_from(target.host.clone())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name '{}'", target.host))?;
    let tls_stream = connector.connect(server_name, tcp).await?;
    Ok(TargetStream::Tls(Box::new(tls_stream)))
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

fn is_hop_by_hop(name: &HeaderName, preserve_upgrade: bool) -> bool {
    let lower = name.as_str().to_ascii_lowercase();
    if preserve_upgrade && (lower == "connection" || lower == "upgrade") {
        return false;
    }
    HOP_BY_HOP_HEADERS.contains(&lower.as_str())
}

fn plain_error_response(status: StatusCode, msg: String) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(msg))
        .map_err(|never| match never {})
        .boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(body)
        .expect("valid error response")
}

/// Serve a single inbound Yamux stream carrying an HTTP/1.1 exchange (or upgraded WS stream)
/// by proxying directly to the local target service.
pub async fn handle_yamux_stream(stream: yamux::Stream, target: Arc<TargetConfig>) {
    let io = TokioIo::new(stream.compat());
    let service = service_fn(move |req: Request<Incoming>| {
        let target = target.clone();
        async move { Ok::<_, Infallible>(forward_http_request(req, target).await) }
    });

    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        debug!("yamux stream http1 server ended: {e}");
    }
}

async fn forward_http_request(
    mut req: Request<Incoming>,
    target: Arc<TargetConfig>,
) -> Response<ProxyBody> {
    let started_at = Instant::now();
    let is_upgrade = is_upgrade_request(req.headers());
    let is_ws = is_upgrade
        && req
            .headers()
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

    let orig_path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let log_method = if is_ws {
        "WS".to_string()
    } else {
        req.method().to_string()
    };

    let client_on_upgrade = if is_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let target_io = match connect_target(&target).await {
        Ok(io) => io,
        Err(e) => {
            let ms = started_at.elapsed().as_millis() as u64;
            ui::log_request(&log_method, &orig_path, 502, ms);
            return plain_error_response(
                StatusCode::BAD_GATEWAY,
                format!(
                    "neruton: failed to connect to local service {}: {e}",
                    target.url
                ),
            );
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(target_io))
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            let ms = started_at.elapsed().as_millis() as u64;
            ui::log_request(&log_method, &orig_path, 502, ms);
            return plain_error_response(
                StatusCode::BAD_GATEWAY,
                format!("neruton: local service HTTP handshake failed: {e}"),
            );
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            debug!("local upstream connection closed: {e}");
        }
    });

    let forward_path = if target.base_path.is_empty() {
        orig_path.clone()
    } else if orig_path.starts_with('/') {
        format!("{}{}", target.base_path, orig_path)
    } else {
        format!("{}/{}", target.base_path, orig_path)
    };
    let forward_uri: Uri = forward_path
        .parse()
        .unwrap_or_else(|_| Uri::from_static("/"));

    let (parts, body) = req.into_parts();
    let mut out_builder = Request::builder()
        .method(parts.method)
        .uri(forward_uri)
        .version(Version::HTTP_11);

    if let Some(headers) = out_builder.headers_mut() {
        for (name, value) in &parts.headers {
            if is_hop_by_hop(name, is_upgrade) {
                continue;
            }
            if *name == header::HOST {
                match &target.host_header_mode {
                    HostHeaderMode::Preserve => {
                        headers.append(name.clone(), value.clone());
                    }
                    HostHeaderMode::RewriteToTarget | HostHeaderMode::Custom(_) => {
                        continue;
                    }
                }
                continue;
            }
            headers.append(name.clone(), value.clone());
        }

        match &target.host_header_mode {
            HostHeaderMode::RewriteToTarget => {
                if let Ok(hv) = HeaderValue::from_str(&target.default_host_header) {
                    headers.insert(header::HOST, hv);
                }
            }
            HostHeaderMode::Custom(custom) => {
                if let Ok(hv) = HeaderValue::from_str(custom) {
                    headers.insert(header::HOST, hv);
                }
            }
            HostHeaderMode::Preserve => {}
        }
    }

    let out_req = match out_builder.body(body) {
        Ok(r) => r,
        Err(e) => {
            return plain_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("neruton: invalid forwarded request: {e}"),
            );
        }
    };

    let mut resp = match sender.send_request(out_req).await {
        Ok(r) => r,
        Err(e) => {
            let ms = started_at.elapsed().as_millis() as u64;
            ui::log_request(&log_method, &orig_path, 502, ms);
            return plain_error_response(
                StatusCode::BAD_GATEWAY,
                format!("neruton: local service request failed: {e}"),
            );
        }
    };

    let status = resp.status();
    let ms = started_at.elapsed().as_millis() as u64;
    ui::log_request(&log_method, &orig_path, status.as_u16(), ms);

    if status == StatusCode::SWITCHING_PROTOCOLS {
        let upstream_on_upgrade = hyper::upgrade::on(&mut resp);
        if let Some(client_upgrade) = client_on_upgrade {
            tokio::spawn(async move {
                match tokio::try_join!(client_upgrade, upstream_on_upgrade) {
                    Ok((c, u)) => {
                        let mut c = TokioIo::new(c);
                        let mut u = TokioIo::new(u);
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
                    }
                    Err(e) => debug!("local upgrade bridge error: {e}"),
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
        return builder.body(resp_body.boxed()).expect("valid 101 response");
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
        .body(resp_body.boxed())
        .expect("valid proxied response")
}
