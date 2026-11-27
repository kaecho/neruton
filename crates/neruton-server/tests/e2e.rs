use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
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
    AuthStatusResponse, AuthUserResponse, HealthResponse, LogsResponse, RegisterRequest,
    RegisterResponse, ServerEvent, ServerInfo, SettingsResponse, SetupResponse,
    TokenCreatedResponse, TokenResponse, TokensResponse, TunnelInfo, TunnelsResponse, UserResponse,
    UserRole, UsersResponse, WsByteStream, YamuxServer, VERSION,
};
use neruton_server::{build_app, AppState, ServerConfig};
use serde_json::json;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as TungMsg;
use tokio_util::compat::FuturesAsyncReadCompatExt;

struct TempDataDir(PathBuf);

impl TempDataDir {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("neruton-server-test-{}", uuid::Uuid::new_v4()));
        Self(dir)
    }

    fn path(&self) -> PathBuf {
        self.0.clone()
    }
}

impl Drop for TempDataDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_config(data_dir: PathBuf) -> ServerConfig {
    ServerConfig {
        data_dir,
        public_scheme: "http".to_string(),
        ..ServerConfig::default()
    }
}

fn cookie_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn spawn_test_server(config: ServerConfig) -> (SocketAddr, Arc<AppState>, JoinHandle<()>) {
    let state = AppState::new(config).unwrap();
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

async fn setup_admin_client(server_addr: SocketAddr) -> (reqwest::Client, SetupResponse) {
    let client = cookie_client();
    let resp = client
        .post(format!("http://{server_addr}/_neruton/api/auth/setup"))
        .json(&json!({
            "username": "admin",
            "password": "AdminPassword123!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let setup: SetupResponse = resp.json().await.unwrap();
    (client, setup)
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
        client_version: "0.4.0-test".to_string(),
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
async fn first_run_setup_login_logout_password_change_and_cors_cookie_flags() {
    let tmp = TempDataDir::new();
    let (server_addr, _state, _s) = spawn_test_server(test_config(tmp.path())).await;
    let client_a = cookie_client();

    // 1. Fresh state needs_setup == true, unauthenticated
    let status: AuthStatusResponse = client_a
        .get(format!("http://{server_addr}/_neruton/api/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(status.needs_setup);
    assert!(!status.authenticated);
    assert!(status.user.is_none());
    assert_eq!(status.version, VERSION);

    // 2. Protected endpoints reject unauthenticated requests with 401
    for path in [
        "/_neruton/api/auth/me",
        "/_neruton/api/info",
        "/_neruton/api/tunnels",
        "/_neruton/api/tokens",
        "/_neruton/api/users",
        "/_neruton/api/settings",
        "/_neruton/api/logs",
        "/_neruton/api/events",
    ] {
        let res = client_a
            .get(format!("http://{server_addr}{path}"))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401, "expected 401 on {path}");
    }

    // 3. Setup validation rejects short username / short password
    let bad_user = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/setup"))
        .json(&json!({"username": "ab", "password": "ValidPassword123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_user.status(), 400);

    let bad_pw = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/setup"))
        .json(&json!({"username": "admin", "password": "short"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_pw.status(), 400);

    // 4. Successful first-run setup returns 201 + initial token + sets session cookie
    let setup_resp = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/setup"))
        .header("Origin", "http://localhost:3000")
        .json(&json!({"username": "admin", "password": "InitialPassword123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(setup_resp.status(), 201);
    assert_eq!(
        setup_resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("http://localhost:3000")
    );
    assert_eq!(
        setup_resp
            .headers()
            .get("access-control-allow-credentials")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    let set_cookie = setup_resp
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("neruton_session="));
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    assert!(set_cookie.contains("Max-Age=604800"));
    assert!(!set_cookie.contains("Secure"));

    let setup: SetupResponse = setup_resp.json().await.unwrap();
    assert_eq!(setup.user.username, "admin");
    assert_eq!(setup.user.role, UserRole::Admin);
    assert!(setup.initial_token.secret.starts_with("ntk_"));
    assert_eq!(setup.initial_token.token.name, "Default CLI Token");

    // 5. Repeat setup returns 409 Conflict
    let repeat_setup = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/setup"))
        .json(&json!({"username": "admin2", "password": "AnotherPassword123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(repeat_setup.status(), 409);

    // 6. Auth status and /me reflect authenticated session
    let status_after: AuthStatusResponse = client_a
        .get(format!("http://{server_addr}/_neruton/api/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!status_after.needs_setup);
    assert!(status_after.authenticated);
    assert_eq!(status_after.user.unwrap().username, "admin");

    let me: AuthUserResponse = client_a
        .get(format!("http://{server_addr}/_neruton/api/auth/me"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me.user.username, "admin");

    // 7. Logout clears cookie
    let logout_resp = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/logout"))
        .send()
        .await
        .unwrap();
    assert_eq!(logout_resp.status(), 200);
    let me_after_logout = client_a
        .get(format!("http://{server_addr}/_neruton/api/auth/me"))
        .send()
        .await
        .unwrap();
    assert_eq!(me_after_logout.status(), 401);

    // 8. Wrong password login -> 401; valid login -> 200 + Secure cookie when X-Forwarded-Proto: https
    let bad_login = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/login"))
        .json(&json!({"username": "admin", "password": "WrongPassword123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_login.status(), 401);

    let secure_login = reqwest::Client::new()
        .post(format!("http://{server_addr}/_neruton/api/auth/login"))
        .header("X-Forwarded-Proto", "https")
        .json(&json!({"username": "admin", "password": "InitialPassword123"}))
        .send()
        .await
        .unwrap();
    assert_eq!(secure_login.status(), 200);
    let secure_cookie = secure_login
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(secure_cookie.contains("; Secure"));

    // 9. Password change bumps token_version: refreshes current client, invalidates other session
    let client_b = cookie_client();
    assert_eq!(
        client_a
            .post(format!("http://{server_addr}/_neruton/api/auth/login"))
            .json(&json!({"username": "admin", "password": "InitialPassword123"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client_b
            .post(format!("http://{server_addr}/_neruton/api/auth/login"))
            .json(&json!({"username": "admin", "password": "InitialPassword123"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // Wrong current password -> 400
    let wrong_pw_chg = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/password"))
        .json(&json!({
            "current_password": "NotThePassword",
            "new_password": "UpdatedPassword456!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_pw_chg.status(), 400);

    // Correct current password -> 200
    let ok_pw_chg = client_a
        .post(format!("http://{server_addr}/_neruton/api/auth/password"))
        .json(&json!({
            "current_password": "InitialPassword123",
            "new_password": "UpdatedPassword456!"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(ok_pw_chg.status(), 200);

    // client_a stays valid with refreshed cookie, client_b is invalidated (401)!
    assert_eq!(
        client_a
            .get(format!("http://{server_addr}/_neruton/api/auth/me"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client_b
            .get(format!("http://{server_addr}/_neruton/api/auth/me"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
}

#[tokio::test]
async fn default_require_auth_user_token_master_token_and_live_open_mode_toggle() {
    let tmp = TempDataDir::new();
    let (backend_addr, _b) = spawn_local_backend().await;
    let mut cfg = test_config(tmp.path());
    cfg.auth_token = Some("legacy-master-secret".to_string());
    let (server_addr, _state, _s) = spawn_test_server(cfg).await;

    let (admin, setup) = setup_admin_client(server_addr).await;
    let user_token = setup.initial_token.secret.clone();

    // 1. Default require_tunnel_auth == true rejects anonymous & wrong token with 401
    let anon_err = connect_test_tunnel(server_addr, backend_addr, Some("anon-fail"), None, None)
        .await
        .unwrap_err();
    assert!(anon_err.contains("401"), "expected 401, got {anon_err}");

    let bad_err = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("bad-tok"),
        Some("ntk_wrongtoken"),
        None,
    )
    .await
    .unwrap_err();
    assert!(bad_err.contains("401"), "expected 401, got {bad_err}");

    // 2. Valid user token (Bearer) succeeds, populates owner/token metadata, updates last_used_at
    let (reg, _t1) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("user-app"),
        Some(&user_token),
        None,
    )
    .await
    .unwrap();
    assert!(reg.ok);
    assert_eq!(reg.owner_username.as_deref(), Some("admin"));
    assert_eq!(reg.token_name.as_deref(), Some("Default CLI Token"));

    // Valid user token via ?token= also works (auto UUID prefix)
    let (reg_uuid, _t2) =
        connect_test_tunnel(server_addr, backend_addr, None, None, Some(&user_token))
            .await
            .unwrap();
    assert!(reg_uuid.ok);
    assert!(uuid::Uuid::parse_str(&reg_uuid.prefix).is_ok());

    // Legacy NERUTON_AUTH_TOKEN also works
    let (reg_master, _t3) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("master-app"),
        Some("legacy-master-secret"),
        None,
    )
    .await
    .unwrap();
    assert!(reg_master.ok);
    assert_eq!(reg_master.token_name.as_deref(), Some("NERUTON_AUTH_TOKEN"));

    let tunnel_info: TunnelInfo = admin
        .get(format!(
            "http://{server_addr}/_neruton/api/tunnels/user-app"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(tunnel_info.owner_username.as_deref(), Some("admin"));
    assert_eq!(tunnel_info.token_name.as_deref(), Some("Default CLI Token"));

    let tokens: TokensResponse = admin
        .get(format!("http://{server_addr}/_neruton/api/tokens"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(tokens.tokens.len(), 1);
    assert!(tokens.tokens[0].last_used_at.is_some());
    assert!(tokens.tokens[0].token_prefix.starts_with("ntk_"));
    assert!(tokens.tokens[0].token_prefix.ends_with("..."));

    // 3. Health & Info reflect require_tunnel_auth == true
    let health: HealthResponse = admin
        .get(format!("http://{server_addr}/_neruton/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health.status, "ok");
    assert_eq!(health.version, VERSION);
    assert!(health.auth_required);
    assert_eq!(health.active_tunnels, 3);

    // 4. Toggle require_tunnel_auth = false live via PATCH /_neruton/api/settings
    let updated_settings: SettingsResponse = admin
        .patch(format!("http://{server_addr}/_neruton/api/settings"))
        .json(&json!({"require_tunnel_auth": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!updated_settings.require_tunnel_auth);
    assert!(updated_settings.env_token_configured);

    // Anonymous tunnel now succeeds!
    let (anon_ok, _t4) =
        connect_test_tunnel(server_addr, backend_addr, Some("open-app"), None, None)
            .await
            .unwrap();
    assert!(anon_ok.ok);
    assert!(anon_ok.owner_username.is_none());

    let info: ServerInfo = admin
        .get(format!("http://{server_addr}/_neruton/api/info"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!info.require_tunnel_auth);
    assert!(!info.auth_required);
    assert_eq!(info.total_users, 1);
    assert_eq!(info.total_tokens, 1);

    // Toggle back ON -> anonymous rejected again
    assert_eq!(
        admin
            .patch(format!("http://{server_addr}/_neruton/api/settings"))
            .json(&json!({"require_tunnel_auth": true}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(
        connect_test_tunnel(server_addr, backend_addr, Some("anon-again"), None, None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn token_allowed_prefixes_disable_delete_disconnect_and_max_tunnels_quota() {
    let tmp = TempDataDir::new();
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(test_config(tmp.path())).await;
    let (admin, _setup) = setup_admin_client(server_addr).await;

    // Create a token restricted to ["alpha", "beta"]
    let created: TokenCreatedResponse = admin
        .post(format!("http://{server_addr}/_neruton/api/tokens"))
        .json(&json!({
            "name": "Scoped Token",
            "allowed_prefixes": ["alpha", "beta"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created.token.allowed_prefixes, vec!["alpha", "beta"]);

    // Auto-UUID rejected on prefix-restricted token
    let (uuid_rej, _) =
        connect_test_tunnel(server_addr, backend_addr, None, Some(&created.secret), None)
            .await
            .unwrap();
    assert!(!uuid_rej.ok);
    assert!(uuid_rej.error.unwrap().contains("restricted"));

    // Unlisted prefix rejected
    let (gamma_rej, _) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("gamma"),
        Some(&created.secret),
        None,
    )
    .await
    .unwrap();
    assert!(!gamma_rej.ok);
    assert!(gamma_rej.error.unwrap().contains("not permitted"));

    // Allowed prefix succeeds and serves traffic
    let (alpha_ok, _t_alpha) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("alpha"),
        Some(&created.secret),
        None,
    )
    .await
    .unwrap();
    assert!(alpha_ok.ok);

    let r = admin
        .get(format!("http://{server_addr}/hello"))
        .header("Host", "alpha.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Disable token -> immediately disconnects active "alpha" tunnel and blocks reconnect
    let patched: TokenResponse = admin
        .patch(format!(
            "http://{server_addr}/_neruton/api/tokens/{}",
            created.token.id
        ))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!patched.token.enabled);

    let r_offline = admin
        .get(format!("http://{server_addr}/hello"))
        .header("Host", "alpha.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(r_offline.status(), 502);

    assert!(connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("alpha"),
        Some(&created.secret),
        None,
    )
    .await
    .is_err());

    // Re-enable token, enforce max_tunnels_per_user = 1
    assert_eq!(
        admin
            .patch(format!(
                "http://{server_addr}/_neruton/api/tokens/{}",
                created.token.id
            ))
            .json(&json!({"enabled": true}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        admin
            .patch(format!("http://{server_addr}/_neruton/api/settings"))
            .json(&json!({"max_tunnels_per_user": 1}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let (alpha_re, _t_alpha2) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("alpha"),
        Some(&created.secret),
        None,
    )
    .await
    .unwrap();
    assert!(alpha_re.ok);

    // Second concurrent tunnel for same user rejected by max_tunnels_per_user == 1
    let (beta_rej, _) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("beta"),
        Some(&created.secret),
        None,
    )
    .await
    .unwrap();
    assert!(!beta_rej.ok);
    assert!(beta_rej.error.unwrap().contains("limit reached"));

    // Deleting token immediately disconnects "alpha" tunnel and rejects reconnect
    assert_eq!(
        admin
            .delete(format!(
                "http://{server_addr}/_neruton/api/tokens/{}",
                created.token.id
            ))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    let r_after_del = admin
        .get(format!("http://{server_addr}/hello"))
        .header("Host", "alpha.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(r_after_del.status(), 502);

    assert!(connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("alpha"),
        Some(&created.secret),
        None,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn rbac_user_crud_scoping_sse_filtering_and_last_admin_protection() {
    let tmp = TempDataDir::new();
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(test_config(tmp.path())).await;
    let (admin, setup) = setup_admin_client(server_addr).await;

    // 1. Admin cannot disable/demote/delete last enabled admin
    assert_eq!(
        admin
            .patch(format!(
                "http://{server_addr}/_neruton/api/users/{}",
                setup.user.id
            ))
            .json(&json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        admin
            .patch(format!(
                "http://{server_addr}/_neruton/api/users/{}",
                setup.user.id
            ))
            .json(&json!({"role": "user"}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        admin
            .delete(format!(
                "http://{server_addr}/_neruton/api/users/{}",
                setup.user.id
            ))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );

    // 2. Admin creates regular user `alice` (duplicate -> 409)
    let alice_created: UserResponse = admin
        .post(format!("http://{server_addr}/_neruton/api/users"))
        .json(&json!({
            "username": "alice",
            "password": "AlicePassword123!",
            "role": "user"
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_created.user.user.username, "alice");
    assert_eq!(alice_created.user.user.role, UserRole::User);

    assert_eq!(
        admin
            .post(format!("http://{server_addr}/_neruton/api/users"))
            .json(&json!({
                "username": "ALICE",
                "password": "AlicePassword123!",
                "role": "user"
            }))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );

    // 3. Alice logs in and is blocked from admin endpoints (403)
    let alice = cookie_client();
    assert_eq!(
        alice
            .post(format!("http://{server_addr}/_neruton/api/auth/login"))
            .json(&json!({"username": "alice", "password": "AlicePassword123!"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        alice
            .get(format!("http://{server_addr}/_neruton/api/users"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        alice
            .patch(format!("http://{server_addr}/_neruton/api/settings"))
            .json(&json!({"require_tunnel_auth": false}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        alice
            .delete(format!("http://{server_addr}/_neruton/api/logs"))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    // Alice CAN read settings
    assert_eq!(
        alice
            .get(format!("http://{server_addr}/_neruton/api/settings"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // 4. Alice creates her own token; both admin and alice connect tunnels
    let alice_tok: TokenCreatedResponse = alice
        .post(format!("http://{server_addr}/_neruton/api/tokens"))
        .json(&json!({"name": "Alice CLI"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Alice cannot see or modify admin's token
    let alice_tokens: TokensResponse = alice
        .get(format!("http://{server_addr}/_neruton/api/tokens"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_tokens.tokens.len(), 1);
    assert_eq!(alice_tokens.tokens[0].id, alice_tok.token.id);
    assert_eq!(
        alice
            .delete(format!(
                "http://{server_addr}/_neruton/api/tokens/{}",
                setup.initial_token.token.id
            ))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    // Subscribe Alice to SSE BEFORE connecting both tunnels
    let alice_sse = alice
        .get(format!("http://{server_addr}/_neruton/api/events"))
        .send()
        .await
        .unwrap();
    assert_eq!(alice_sse.status(), 200);
    let mut alice_stream = alice_sse.bytes_stream();

    let (admin_reg, _t_admin) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("admin-app"),
        Some(&setup.initial_token.secret),
        None,
    )
    .await
    .unwrap();
    assert!(admin_reg.ok);

    let (alice_reg, _t_alice) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("alice-app"),
        Some(&alice_tok.secret),
        None,
    )
    .await
    .unwrap();
    assert!(alice_reg.ok);

    // Issue traffic to both tunnels
    assert_eq!(
        admin
            .get(format!("http://{server_addr}/hello"))
            .header("Host", "admin-app.moer.eu.org")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        alice
            .get(format!("http://{server_addr}/hello"))
            .header("Host", "alice-app.moer.eu.org")
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // Alice only sees `alice-app` in tunnels & logs, gets 403 on `admin-app`
    let alice_tunnels: TunnelsResponse = alice
        .get(format!("http://{server_addr}/_neruton/api/tunnels"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_tunnels.tunnels.len(), 1);
    assert_eq!(alice_tunnels.tunnels[0].prefix, "alice-app");

    assert_eq!(
        alice
            .get(format!(
                "http://{server_addr}/_neruton/api/tunnels/admin-app"
            ))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        alice
            .delete(format!(
                "http://{server_addr}/_neruton/api/tunnels/admin-app"
            ))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let alice_logs: LogsResponse = alice
        .get(format!("http://{server_addr}/_neruton/api/logs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(alice_logs.logs.len(), 1);
    assert_eq!(alice_logs.logs[0].tunnel_prefix, "alice-app");

    // Admin sees both tunnels, both users with accurate counts, and can clear logs
    let admin_tunnels: TunnelsResponse = admin
        .get(format!("http://{server_addr}/_neruton/api/tunnels"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(admin_tunnels.tunnels.len(), 2);

    let users_list: UsersResponse = admin
        .get(format!("http://{server_addr}/_neruton/api/users"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(users_list.users.len(), 2);
    let alice_view = users_list
        .users
        .iter()
        .find(|u| u.user.username == "alice")
        .unwrap();
    assert_eq!(alice_view.token_count, 1);
    assert_eq!(alice_view.active_tunnel_count, 1);

    assert_eq!(
        admin
            .delete(format!("http://{server_addr}/_neruton/api/logs"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let after_clear: LogsResponse = admin
        .get(format!("http://{server_addr}/_neruton/api/logs"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(after_clear.logs.is_empty());

    // Verify Alice's SSE stream got alice-app events and ZERO admin-app events
    let mut saw_alice_conn = false;
    let mut saw_alice_req = false;
    let mut saw_admin_event = false;
    let mut buf = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(Ok(chunk)) = alice_stream.next().await {
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(idx) = buf.find("\n\n") {
                let frame = buf[..idx].to_string();
                buf.drain(..idx + 2);
                for line in frame.lines() {
                    if let Some(data) = line.strip_prefix("data:") {
                        if let Ok(ev) = serde_json::from_str::<ServerEvent>(data.trim()) {
                            match ev {
                                ServerEvent::TunnelConnected { tunnel } => {
                                    if tunnel.prefix == "alice-app" {
                                        saw_alice_conn = true;
                                    } else if tunnel.prefix == "admin-app" {
                                        saw_admin_event = true;
                                    }
                                }
                                ServerEvent::RequestLogged { log } => {
                                    if log.tunnel_prefix == "alice-app" {
                                        saw_alice_req = true;
                                    } else if log.tunnel_prefix == "admin-app" {
                                        saw_admin_event = true;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                if saw_alice_conn && saw_alice_req {
                    return;
                }
            }
        }
    })
    .await;
    assert!(saw_alice_conn);
    assert!(saw_alice_req);
    assert!(!saw_admin_event, "SSE leaked admin event to regular user");

    // 5. Admin disables Alice -> disconnects alice-app, invalidates session & token
    assert_eq!(
        admin
            .patch(format!(
                "http://{server_addr}/_neruton/api/users/{}",
                alice_created.user.user.id
            ))
            .json(&json!({"enabled": false}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        alice
            .get(format!("http://{server_addr}/_neruton/api/auth/me"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        admin
            .get(format!("http://{server_addr}/hello"))
            .header("Host", "alice-app.moer.eu.org")
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    assert!(connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("alice-app"),
        Some(&alice_tok.secret),
        None,
    )
    .await
    .is_err());

    // 6. Admin deletes Alice -> removes user and her tokens
    assert_eq!(
        admin
            .delete(format!(
                "http://{server_addr}/_neruton/api/users/{}",
                alice_created.user.user.id
            ))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let remaining_tokens: TokensResponse = admin
        .get(format!("http://{server_addr}/_neruton/api/tokens"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(remaining_tokens.tokens.len(), 1);
    assert_eq!(remaining_tokens.tokens[0].id, setup.initial_token.token.id);
}

#[tokio::test]
async fn reserved_prefixes_persistence_across_restart_and_env_admin_bootstrap() {
    let tmp = TempDataDir::new();
    let (backend_addr, _b) = spawn_local_backend().await;

    // 1. Start server #1, setup admin, configure reserved prefixes & settings
    let (addr1, _state1, handle1) = spawn_test_server(test_config(tmp.path())).await;
    let (admin1, setup) = setup_admin_client(addr1).await;
    let token_secret = setup.initial_token.secret.clone();

    let updated: SettingsResponse = admin1
        .patch(format!("http://{addr1}/_neruton/api/settings"))
        .json(&json!({
            "require_tunnel_auth": true,
            "max_tunnels_per_user": 3,
            "reserved_prefixes": ["staging", "internal"]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated.reserved_prefixes, vec!["staging", "internal"]);
    assert_eq!(updated.max_tunnels_per_user, 3);

    // Verify dynamic reserved prefix is rejected live
    let (rej, _) = connect_test_tunnel(
        addr1,
        backend_addr,
        Some("staging"),
        Some(&token_secret),
        None,
    )
    .await
    .unwrap();
    assert!(!rej.ok);
    assert!(rej.error.unwrap().contains("reserved"));

    // Shut down server #1
    handle1.abort();

    // 2. Restart server #2 pointing to the SAME data_dir!
    let (addr2, _state2, _handle2) = spawn_test_server(test_config(tmp.path())).await;
    let admin2 = cookie_client();

    let status2: AuthStatusResponse = admin2
        .get(format!("http://{addr2}/_neruton/api/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!status2.needs_setup);

    // Persisted admin credentials still work
    assert_eq!(
        admin2
            .post(format!("http://{addr2}/_neruton/api/auth/login"))
            .json(&json!({"username": "admin", "password": "AdminPassword123!"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // Persisted settings survive restart
    let settings2: SettingsResponse = admin2
        .get(format!("http://{addr2}/_neruton/api/settings"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(settings2.require_tunnel_auth);
    assert_eq!(settings2.max_tunnels_per_user, 3);
    assert_eq!(settings2.reserved_prefixes, vec!["staging", "internal"]);

    // Persisted reserved prefix still rejected & persisted token still works
    let (rej2, _) = connect_test_tunnel(
        addr2,
        backend_addr,
        Some("internal"),
        Some(&token_secret),
        None,
    )
    .await
    .unwrap();
    assert!(!rej2.ok);
    assert!(rej2.error.unwrap().contains("reserved"));

    let (ok2, _t2) = connect_test_tunnel(
        addr2,
        backend_addr,
        Some("allowed-app"),
        Some(&token_secret),
        None,
    )
    .await
    .unwrap();
    assert!(ok2.ok);

    // 3. Verify NERUTON_ADMIN_PASSWORD env bootstrap on fresh data dir
    let tmp_env = TempDataDir::new();
    let mut env_cfg = test_config(tmp_env.path());
    env_cfg.admin_user = "rootadmin".to_string();
    env_cfg.admin_password = Some("BootstrapPass123!".to_string());
    let (addr_env, _s_env, _h_env) = spawn_test_server(env_cfg).await;

    let env_client = cookie_client();
    let env_status: AuthStatusResponse = env_client
        .get(format!("http://{addr_env}/_neruton/api/auth/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(!env_status.needs_setup);

    assert_eq!(
        env_client
            .post(format!("http://{addr_env}/_neruton/api/auth/login"))
            .json(&json!({"username": "rootadmin", "password": "BootstrapPass123!"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let env_tokens: TokensResponse = env_client
        .get(format!("http://{addr_env}/_neruton/api/tokens"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(env_tokens.tokens.len(), 1);
    assert_eq!(env_tokens.tokens[0].name, "Default CLI Token");
}

#[tokio::test]
async fn custom_subdomain_http_get_post_streaming_path_proxy_ws_and_offline_502() {
    let tmp = TempDataDir::new();
    let (backend_addr, _b) = spawn_local_backend().await;
    let (server_addr, _state, _s) = spawn_test_server(test_config(tmp.path())).await;
    let (admin, setup) = setup_admin_client(server_addr).await;
    let token = setup.initial_token.secret.clone();

    // 1. Custom subdomain HTTP GET/POST/streaming/502
    let (reg, _t) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("Test-Test"),
        Some(&token),
        None,
    )
    .await
    .unwrap();
    assert!(reg.ok);
    assert_eq!(reg.prefix, "test-test");

    let res = admin
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

    let payload = "neruton-post-payload-12345";
    let res = admin
        .post(format!("http://{server_addr}/echo"))
        .header("Host", "test-test.moer.eu.org")
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), payload);

    let res = admin
        .get(format!("http://{server_addr}/stream"))
        .header("Host", "test-test.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "chunk-1|chunk-2|chunk-3");

    // Offline 502 page
    let res = admin
        .get(format!("http://{server_addr}/"))
        .header("Host", "missing-tunnel.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    let html = res.text().await.unwrap();
    assert!(html.contains("missing-tunnel"));

    // 2. Path proxy HTML <base> injection, frame headers stripping, redirects
    let (viewer_reg, _t_v) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("viewer"),
        Some(&token),
        None,
    )
    .await
    .unwrap();
    assert!(viewer_reg.ok);

    let res = admin
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
    let page_html = res.text().await.unwrap();
    assert!(page_html.contains(r#"<head><base href="/t/viewer/"><title>Demo</title></head>"#));

    let redir_res = admin
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

    // 3. WebSocket upgrade over subdomain & path proxy
    let mut ws_req = format!("ws://{server_addr}/ws")
        .into_client_request()
        .unwrap();
    ws_req
        .headers_mut()
        .insert("Host", HeaderValue::from_static("viewer.moer.eu.org"));
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_req).await.unwrap();
    ws.send(TungMsg::Text("ping-sub".into())).await.unwrap();
    assert_eq!(
        ws.next().await.unwrap().unwrap(),
        TungMsg::Text("echo:ping-sub".into())
    );
    let _ = ws.close(None).await;

    let (mut ws2, _) = tokio_tungstenite::connect_async(format!("ws://{server_addr}/t/viewer/ws"))
        .await
        .unwrap();
    ws2.send(TungMsg::Text("ping-path".into())).await.unwrap();
    assert_eq!(
        ws2.next().await.unwrap().unwrap(),
        TungMsg::Text("echo:ping-path".into())
    );
    let _ = ws2.close(None).await;

    // 4. Duplicate & built-in reserved prefix rejection
    for reserved in [
        "neruton", "www", "api", "admin", "_neruton", "bad_name", "-dash",
    ] {
        let (resp, _) = connect_test_tunnel(
            server_addr,
            backend_addr,
            Some(reserved),
            Some(&token),
            None,
        )
        .await
        .unwrap();
        assert!(!resp.ok, "expected '{reserved}' to be rejected");
    }

    let (dup, _) = connect_test_tunnel(
        server_addr,
        backend_addr,
        Some("test-test"),
        Some(&token),
        None,
    )
    .await
    .unwrap();
    assert!(!dup.ok);
    assert!(dup.error.unwrap().contains("already in use"));

    // 5. Verify per-tunnel info & logs recorded
    tokio::time::sleep(Duration::from_millis(50)).await;
    let info: TunnelInfo = admin
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

    let viewer_logs: LogsResponse = admin
        .get(format!(
            "http://{server_addr}/_neruton/api/tunnels/viewer/logs"
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(viewer_logs
        .logs
        .iter()
        .any(|l| l.status == 101 && l.via == "subdomain"));
    assert!(viewer_logs
        .logs
        .iter()
        .any(|l| l.status == 101 && l.via == "path"));
}

#[tokio::test]
async fn web_upstream_reverse_proxy_and_api_priority() {
    let tmp = TempDataDir::new();
    let mock_web = Router::new()
        .route("/", get(|| async { "mock-nextjs-dashboard" }))
        .route("/preview/demo", get(|| async { "mock-nextjs-preview" }));
    let web_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_addr = web_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(web_listener, mock_web).await.unwrap();
    });

    let mut cfg = test_config(tmp.path());
    cfg.web_upstream = Some(format!("http://{web_addr}"));
    let (server_addr, _state, _s) = spawn_test_server(cfg).await;
    let (admin, _setup) = setup_admin_client(server_addr).await;

    let dash = admin
        .get(format!("http://{server_addr}/"))
        .header("Host", "neruton.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(dash.status(), 200);
    assert_eq!(dash.text().await.unwrap(), "mock-nextjs-dashboard");

    let preview = admin
        .get(format!("http://{server_addr}/preview/demo"))
        .header("Host", "neruton.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(preview.status(), 200);
    assert_eq!(preview.text().await.unwrap(), "mock-nextjs-preview");

    // Management API still handled directly by neruton-server
    let info: ServerInfo = admin
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
