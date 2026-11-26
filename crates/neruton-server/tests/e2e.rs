use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message as AxumWsMsg, WebSocketUpgrade};
use axum::http::header::{self, HeaderValue};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use neruton_proto::{
    HealthResponse, LogsResponse, RegisterRequest, RegisterResponse, ServerEvent, ServerInfo,
    TunnelInfo, TunnelsResponse, WsByteStream, YamuxServer,
};
use neruton_server::{build_app, AppState, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as TungMsg;
use tokio_util::compat::FuturesAsyncReadCompatExt;

async fn spawn_test_server(config: ServerConfig) -> (SocketAddr, Arc<AppState>, JoinHandle<()>) {
    let state = AppState::new(config);
    let app = build_app(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (addr, state, handle)
}

async fn spawn_local_backend() -> (SocketAddr, JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/hello",
            get(|headers: HeaderMap, uri: axum::http::Uri| async move {
                let xf_host = headers
                    .get("x-forwarded-host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let query = uri.query().unwrap_or("").to_string();
                (
                    [(header::HeaderName::from_static("x-backend"), "ok")],
                    format!("hello|q={query}|xfh={xf_host}"),
                )
            }),
        )
        .route(
            "/echo",
            post(|body: Bytes| async move {
                (
                    [(header::CONTENT_TYPE, "application/octet-stream")],
                    body,
                )
            }),
        )
        .route(
            "/stream",
            get(|| async move {
                let chunks = futures_util::stream::iter(vec![
                    Ok::<_, Infallible>(Bytes::from_static(b"chunk-1|")),
                    Ok::<_, Infallible>(Bytes::from_static(b"chunk-2|")),
                    Ok::<_, Infallible>(Bytes::from_static(b"chunk-3")),
                ]);
                Body::from_stream(chunks)
            }),
        )
        .route(
            "/page",
            get(|| async move {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
                headers.insert(
                    header::HeaderName::from_static("x-frame-options"),
                    HeaderValue::from_static("DENY"),
                );
                headers.insert(
                    header::HeaderName::from_static("content-security-policy"),
                    HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'"),
                );
                (
                    headers,
                    "<!doctype html><html><head><title>Demo</title></head><body>Hello Tunnel</body></html>",
                )
            }),
        )
        .route(
            "/redir",
            get(|| async move {
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "/dashboard?ok=1")],
                    "",
                )
            }),
        )
        .route(
            "/ws",
            get(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut socket| async move {
                    while let Some(Ok(msg)) = socket.recv().await {
                        match msg {
                            AxumWsMsg::Text(t) => {
                                let reply = format!("echo:{t}");
                                if socket.send(AxumWsMsg::Text(reply.into())).await.is_err() {
                                    break;
                                }
                            }
                            AxumWsMsg::Close(_) => break,
                            _ => {}
                        }
                    }
                })
            }),
        )
        .route(
            "/",
            get(|| async move {
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html><head></head><body>root-index</body></html>",
                )
            }),
        );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, handle)
}

/// Connect a test Yamux-over-WebSocket tunnel client forwarding all Yamux streams to `backend_addr`.
async fn connect_test_tunnel(
    server_addr: SocketAddr,
    backend_addr: SocketAddr,
    prefix: Option<&str>,
    bearer_token: Option<&str>,
    query_token: Option<&str>,
) -> Result<(RegisterResponse, JoinHandle<()>), String> {
    let mut url = format!("ws://{server_addr}/_neruton/tunnel");
    if let Some(qt) = query_token {
        url.push_str(&format!("?token={qt}"));
    }
    let mut req = url.into_client_request().unwrap();
    if let Some(bt) = bearer_token {
        req.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {bt}")).unwrap(),
        );
    }

    let (mut ws, _) = tokio_tungstenite::connect_async(req)
        .await
        .map_err(|e| format!("ws connect error: {e}"))?;

    let reg = RegisterRequest {
        prefix: prefix.map(str::to_string),
        target_url: format!("http://{backend_addr}"),
        client_version: "0.1.0-test".to_string(),
        client_os: "linux/x86_64".to_string(),
    };
    ws.send(TungMsg::Text(serde_json::to_string(&reg).unwrap().into()))
        .await
        .map_err(|e| format!("send reg error: {e}"))?;

    let resp: RegisterResponse = match ws.next().await {
        Some(Ok(TungMsg::Text(text))) => serde_json::from_str(&text).unwrap(),
        other => return Err(format!("unexpected register reply: {other:?}")),
    };

    if !resp.ok {
        return Ok((resp, tokio::spawn(async {})));
    }

    let mut yamux_server = YamuxServer::spawn(WsByteStream::new(ws));
    let task = tokio::spawn(async move {
        while let Some(stream) = yamux_server.accept().await {
            tokio::spawn(async move {
                let io = TokioIo::new(stream.compat());
                let svc = service_fn(move |mut req: hyper::Request<Incoming>| async move {
                    let is_upgrade = req.headers().contains_key(header::UPGRADE);
                    let client_upgrade = if is_upgrade {
                        Some(hyper::upgrade::on(&mut req))
                    } else {
                        None
                    };

                    let tcp = TcpStream::connect(backend_addr).await.unwrap();
                    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
                        .handshake(TokioIo::new(tcp))
                        .await
                        .unwrap();
                    tokio::spawn(async move {
                        let _ = conn.with_upgrades().await;
                    });

                    req.headers_mut().insert(
                        header::HOST,
                        HeaderValue::from_str(&backend_addr.to_string()).unwrap(),
                    );
                    let mut resp = sender.send_request(req).await.unwrap();
                    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
                        let up_upgrade = hyper::upgrade::on(&mut resp);
                        if let Some(cl_upgrade) = client_upgrade {
                            tokio::spawn(async move {
                                if let Ok((c, u)) = tokio::try_join!(cl_upgrade, up_upgrade) {
                                    let mut c = TokioIo::new(c);
                                    let mut u = TokioIo::new(u);
                                    let _ = tokio::io::copy_bidirectional(&mut c, &mut u).await;
                                }
                            });
                        }
                    }
                    let (parts, body) = resp.into_parts();
                    let boxed = body.boxed();
                    let out = hyper::Response::from_parts(parts, boxed);
                    if out.status() == StatusCode::INTERNAL_SERVER_ERROR {
                        let _ = Full::new(Bytes::new());
                    }
                    Ok::<_, Infallible>(out)
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .with_upgrades()
                    .await;
            });
        }
    });

    Ok((resp, task))
}

#[tokio::test]
async fn default_uuid_prefix_and_wildcard_and_health() {
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(ServerConfig::default()).await;

    let (reg, _t) = connect_test_tunnel(server_addr, backend_addr, None, None, None)
        .await
        .unwrap();
    assert!(reg.ok);
    assert!(uuid::Uuid::parse_str(&reg.prefix).is_ok());
    assert_eq!(
        reg.public_url,
        format!("https://{}.moer.eu.org", reg.prefix)
    );
    assert_eq!(
        reg.path_url,
        format!("https://neruton.moer.eu.org/t/{}/", reg.prefix)
    );
    assert_eq!(
        reg.preview_url,
        format!("https://neruton.moer.eu.org/preview/{}", reg.prefix)
    );

    let client = reqwest::Client::new();
    let health: HealthResponse = client
        .get(format!("http://{server_addr}/_neruton/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health.status, "ok");
    assert_eq!(health.active_tunnels, 1);
    assert!(!health.auth_required);

    let tunnels: TunnelsResponse = client
        .get(format!("http://{server_addr}/_neruton/api/tunnels"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(tunnels.tunnels.len(), 1);
    assert_eq!(tunnels.tunnels[0].prefix, reg.prefix);
    assert_eq!(tunnels.tunnels[0].status, "online");

    // Wildcard Host routing using auto-generated UUID prefix
    let resp = client
        .get(format!("http://{server_addr}/hello?auto=1"))
        .header("Host", format!("{}.moer.eu.org", reg.prefix))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("hello|q=auto=1|xfh="));
}

#[tokio::test]
async fn custom_subdomain_http_get_post_streaming_and_offline_502() {
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(ServerConfig::default()).await;

    let (reg, _t) = connect_test_tunnel(server_addr, backend_addr, Some("Test-Test"), None, None)
        .await
        .unwrap();
    assert!(reg.ok);
    assert_eq!(reg.prefix, "test-test");

    let client = reqwest::Client::new();

    // GET
    let res = client
        .get(format!("http://{server_addr}/hello?k=v"))
        .header("Host", "test-test.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(
        res.headers().get("x-backend").and_then(|v| v.to_str().ok()),
        Some("ok")
    );
    assert_eq!(
        res.text().await.unwrap(),
        "hello|q=k=v|xfh=test-test.moer.eu.org"
    );

    // POST
    let payload = "neruton-post-payload-12345";
    let res = client
        .post(format!("http://{server_addr}/echo"))
        .header("Host", "test-test.moer.eu.org")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), payload);

    // Streaming response
    let res = client
        .get(format!("http://{server_addr}/stream"))
        .header("Host", "test-test.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "chunk-1|chunk-2|chunk-3");

    // Offline 502 page
    let res = client
        .get(format!("http://{server_addr}/"))
        .header("Host", "missing-tunnel.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    let html = res.text().await.unwrap();
    assert!(html.contains("missing-tunnel"));
    assert!(html.contains("https://neruton.moer.eu.org/"));

    // Verify per-tunnel info & logs recorded
    tokio::time::sleep(Duration::from_millis(50)).await;
    let info: TunnelInfo = client
        .get(format!(
            "http://{server_addr}/_neruton/api/tunnels/test-test"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.requests_total, 3);
    assert!(info.bytes_in > 0);
    assert!(info.bytes_out > 0);
}

#[tokio::test]
async fn path_proxy_html_base_injection_frame_headers_and_redirects() {
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(ServerConfig::default()).await;

    let (reg, _t) = connect_test_tunnel(server_addr, backend_addr, Some("viewer"), None, None)
        .await
        .unwrap();
    assert!(reg.ok);

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // HTML <base> injection & frame header stripping
    let res = client
        .get(format!("http://{server_addr}/t/viewer/page"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert!(res.headers().get("x-frame-options").is_none());
    assert_eq!(
        res.headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'self'")
    );
    let html = res.text().await.unwrap();
    assert!(html.contains(r#"<head><base href="/t/viewer/"><title>Demo</title></head>"#));

    // Bare `/t/viewer` maps to `/` and injects `<base>`
    let root_res = client
        .get(format!("http://{server_addr}/t/viewer"))
        .send()
        .await
        .unwrap();
    assert_eq!(root_res.status(), 200);
    let root_html = root_res.text().await.unwrap();
    assert!(root_html.contains(r#"<base href="/t/viewer/">"#));
    assert!(root_html.contains("root-index"));

    // Relative Location redirect rewrite
    let redir_res = client
        .get(format!("http://{server_addr}/t/viewer/redir"))
        .send()
        .await
        .unwrap();
    assert_eq!(redir_res.status(), 302);
    assert_eq!(
        redir_res
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/t/viewer/dashboard?ok=1")
    );

    // Logs show `via: "path"`
    let logs: LogsResponse = client
        .get(format!(
            "http://{server_addr}/_neruton/api/tunnels/viewer/logs"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(logs.logs.len(), 3);
    assert!(logs.logs.iter().all(|l| l.via == "path"));
}

#[tokio::test]
async fn websocket_upgrade_through_subdomain_and_path_tunnel() {
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(ServerConfig::default()).await;

    let (reg, _t) = connect_test_tunnel(server_addr, backend_addr, Some("ws-demo"), None, None)
        .await
        .unwrap();
    assert!(reg.ok);

    // 1. WebSocket over wildcard subdomain Host
    let mut req = format!("ws://{server_addr}/ws")
        .into_client_request()
        .unwrap();
    req.headers_mut()
        .insert("Host", HeaderValue::from_static("ws-demo.moer.eu.org"));
    let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    ws.send(TungMsg::Text("ping-sub".into())).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert_eq!(reply, TungMsg::Text("echo:ping-sub".into()));
    let _ = ws.close(None).await;

    // 2. WebSocket over path proxy `/t/ws-demo/ws`
    let (mut ws2, _) = tokio_tungstenite::connect_async(format!("ws://{server_addr}/t/ws-demo/ws"))
        .await
        .unwrap();
    ws2.send(TungMsg::Text("ping-path".into())).await.unwrap();
    let reply2 = ws2.next().await.unwrap().unwrap();
    assert_eq!(reply2, TungMsg::Text("echo:ping-path".into()));
    let _ = ws2.close(None).await;

    let client = reqwest::Client::new();
    let logs: LogsResponse = client
        .get(format!(
            "http://{server_addr}/_neruton/api/tunnels/ws-demo/logs"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(logs
        .logs
        .iter()
        .any(|l| l.status == 101 && l.via == "subdomain"));
    assert!(logs.logs.iter().any(|l| l.status == 101 && l.via == "path"));
}

#[tokio::test]
async fn duplicate_and_reserved_prefix_rejection() {
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(ServerConfig::default()).await;

    for reserved in [
        "neruton", "www", "api", "admin", "_neruton", "bad_name", "-dash",
    ] {
        let (resp, _) = connect_test_tunnel(server_addr, backend_addr, Some(reserved), None, None)
            .await
            .unwrap();
        assert!(!resp.ok, "expected '{reserved}' to be rejected");
        assert!(resp.error.is_some());
    }

    let (first, _t1) = connect_test_tunnel(server_addr, backend_addr, Some("unique-1"), None, None)
        .await
        .unwrap();
    assert!(first.ok);

    let (dup, _) = connect_test_tunnel(server_addr, backend_addr, Some("unique-1"), None, None)
        .await
        .unwrap();
    assert!(!dup.ok);
    assert!(dup.error.unwrap().contains("already in use"));
}

#[tokio::test]
async fn auth_token_enforcement_delete_and_sse_events() {
    let (backend_addr, _b) = spawn_local_backend().await;
    let cfg = ServerConfig {
        auth_token: Some("secret-xyz".to_string()),
        ..ServerConfig::default()
    };
    let (server_addr, _state, _s) = spawn_test_server(cfg).await;

    // Missing / wrong token rejected with 401
    assert!(
        connect_test_tunnel(server_addr, backend_addr, Some("auth-app"), None, None)
            .await
            .is_err()
    );
    assert!(connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("auth-app"),
        Some("wrong"),
        None
    )
    .await
    .is_err());

    // Subscribe to SSE before tunnel lifecycle events
    let client = reqwest::Client::new();
    let sse_resp = client
        .get(format!("http://{server_addr}/_neruton/api/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), 200);
    let mut sse_stream = sse_resp.bytes_stream();

    // Valid Bearer token succeeds
    let (reg, _t) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("auth-app"),
        Some("secret-xyz"),
        None,
    )
    .await
    .unwrap();
    assert!(reg.ok);

    // Valid ?token= also succeeds
    let (reg2, _t2) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("auth-app-2"),
        None,
        Some("secret-xyz"),
    )
    .await
    .unwrap();
    assert!(reg2.ok);

    // Issue a proxied request
    let r = client
        .get(format!("http://{server_addr}/hello"))
        .header("Host", "auth-app.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // DELETE without token -> 401
    let del_unauth = client
        .delete(format!(
            "http://{server_addr}/_neruton/api/tunnels/auth-app"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(del_unauth.status(), 401);

    // DELETE with valid token -> 200 and tunnel disconnects
    let del_ok = client
        .delete(format!(
            "http://{server_addr}/_neruton/api/tunnels/auth-app"
        ))
        .header("Authorization", "Bearer secret-xyz")
        .send()
        .await
        .unwrap();
    assert_eq!(del_ok.status(), 200);

    // Subsequent wildcard request returns 502
    let after_del = client
        .get(format!("http://{server_addr}/hello"))
        .header("Host", "auth-app.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(after_del.status(), 502);

    // Verify SSE delivered connected, request_logged, and disconnected events
    let mut saw_connected = false;
    let mut saw_logged = false;
    let mut saw_disconnected = false;
    let mut buf = String::new();

    let collect_result = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(Ok(chunk)) = sse_stream.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(idx) = buf.find("\n\n") {
                let frame = buf[..idx].to_string();
                buf.drain(..idx + 2);
                for line in frame.lines() {
                    if let Some(data) = line.strip_prefix("data:") {
                        if let Ok(ev) = serde_json::from_str::<ServerEvent>(data.trim()) {
                            match ev {
                                ServerEvent::TunnelConnected { tunnel }
                                    if tunnel.prefix == "auth-app" =>
                                {
                                    saw_connected = true;
                                }
                                ServerEvent::RequestLogged { log }
                                    if log.tunnel_prefix == "auth-app" =>
                                {
                                    saw_logged = true;
                                }
                                ServerEvent::TunnelDisconnected { prefix, .. }
                                    if prefix == "auth-app" =>
                                {
                                    saw_disconnected = true;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if saw_connected && saw_logged && saw_disconnected {
                    return;
                }
            }
        }
    })
    .await;

    assert!(collect_result.is_ok(), "timed out waiting for SSE events");
    assert!(saw_connected);
    assert!(saw_logged);
    assert!(saw_disconnected);
}

#[tokio::test]
async fn web_upstream_reverse_proxy_and_api_priority() {
    let mock_web = Router::new()
        .route("/", get(|| async { "mock-nextjs-dashboard" }))
        .route("/preview/demo", get(|| async { "mock-nextjs-preview" }));
    let web_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_addr = web_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(web_listener, mock_web).await.unwrap();
    });

    let cfg = ServerConfig {
        web_upstream: Some(format!("http://{web_addr}")),
        ..ServerConfig::default()
    };
    let (server_addr, _state, _s) = spawn_test_server(cfg).await;

    let client = reqwest::Client::new();

    let dash = client
        .get(format!("http://{server_addr}/"))
        .header("Host", "neruton.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(dash.status(), 200);
    assert_eq!(dash.text().await.unwrap(), "mock-nextjs-dashboard");

    let preview = client
        .get(format!("http://{server_addr}/preview/demo"))
        .header("Host", "neruton.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status(), 200);
    assert_eq!(preview.text().await.unwrap(), "mock-nextjs-preview");

    // Management API still handled directly by neruton-server
    let info: ServerInfo = client
        .get(format!("http://{server_addr}/_neruton/api/info"))
        .header("Host", "neruton.moer.eu.org")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.panel_host, "neruton.moer.eu.org");
    assert_eq!(info.base_domain, "moer.eu.org");
}
