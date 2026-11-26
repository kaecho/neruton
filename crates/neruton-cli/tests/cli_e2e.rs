use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use axum::extract::ws::{Message as AxumWsMsg, WebSocketUpgrade};
use axum::http::header::{self, HeaderValue};
use axum::http::HeaderMap;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use neruton_proto::TunnelInfo;
use neruton_server::{build_app, AppState, ServerConfig};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message as TungMsg;

#[test]
fn cli_version_and_config_commands() {
    let bin = env!("CARGO_BIN_EXE_neruton");

    let out = std::process::Command::new(bin)
        .arg("version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("neruton "));

    let tmp_cfg =
        std::env::temp_dir().join(format!("neruton-test-cfg-{}.toml", uuid::Uuid::new_v4()));

    let set_out = std::process::Command::new(bin)
        .args([
            "config",
            "set",
            "--server",
            "https://custom.example.com",
            "--token",
            "abc-token",
            "--config",
            tmp_cfg.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(set_out.status.success());

    let show_out = std::process::Command::new(bin)
        .args(["config", "show", "--config", tmp_cfg.to_str().unwrap()])
        .env_remove("NERUTON_SERVER")
        .output()
        .unwrap();
    assert!(show_out.status.success());
    let show_str = String::from_utf8_lossy(&show_out.stdout);
    assert!(show_str.contains("https://custom.example.com"));
    assert!(show_str.contains("<configured>"));

    let _ = std::fs::remove_file(&tmp_cfg);
}

#[tokio::test]
async fn real_cli_binary_end_to_end_http_ws_and_host_header() {
    // 1. Start local target HTTP + WS service
    let target_app = Router::new()
        .route(
            "/whoami",
            get(|headers: HeaderMap| async move {
                let host = headers
                    .get(header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                format!("host={host}")
            }),
        )
        .route(
            "/ws",
            get(|ws: WebSocketUpgrade| async move {
                ws.on_upgrade(|mut socket| async move {
                    while let Some(Ok(AxumWsMsg::Text(msg))) = socket.recv().await {
                        if socket
                            .send(AxumWsMsg::Text(format!("cli-ws:{msg}").into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                })
            }),
        );

    let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let _target_task = tokio::spawn(async move {
        axum::serve(target_listener, target_app).await.unwrap();
    });

    // 2. Start real neruton-server
    let state = AppState::new(ServerConfig::default());
    let server_app = build_app(state.clone());
    let server_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_listener.local_addr().unwrap();
    let _server_task = tokio::spawn(async move {
        axum::serve(
            server_listener,
            server_app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // 3. Launch real `neruton http <port>` binary
    let bin = env!("CARGO_BIN_EXE_neruton");
    let mut child = Command::new(bin)
        .args([
            "http",
            &target_addr.port().to_string(),
            "--server",
            &format!("http://{server_addr}"),
            "--subdomain",
            "cli-e2e",
        ])
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();

    // Wait for tunnel registration
    let client = reqwest::Client::new();
    let mut connected = false;
    for _ in 0..50 {
        let resp = client
            .get(format!("http://{server_addr}/_neruton/api/tunnels/cli-e2e"))
            .send()
            .await
            .unwrap();
        if resp.status() == 200 {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(connected, "neruton CLI failed to register tunnel in time");

    // 4. Test wildcard HTTP request (Host header rewritten to 127.0.0.1:<port>)
    let res = client
        .get(format!("http://{server_addr}/whoami"))
        .header("Host", "cli-e2e.moer.eu.org")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), format!("host={target_addr}"));

    // 5. Test WebSocket upgrade end-to-end through real `neruton` CLI!
    let mut ws_req = format!("ws://{server_addr}/ws")
        .into_client_request()
        .unwrap();
    ws_req
        .headers_mut()
        .insert("Host", HeaderValue::from_static("cli-e2e.moer.eu.org"));
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_req).await.unwrap();
    ws.send(TungMsg::Text("hello".into())).await.unwrap();
    let msg = ws.next().await.unwrap().unwrap();
    assert_eq!(msg, TungMsg::Text("cli-ws:hello".into()));
    let _ = ws.close(None).await;

    // 6. Wait briefly so initial 200ms WS ping/pong heartbeat runs and check TunnelInfo
    tokio::time::sleep(Duration::from_millis(350)).await;
    let info: TunnelInfo = client
        .get(format!("http://{server_addr}/_neruton/api/tunnels/cli-e2e"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(info.prefix, "cli-e2e");
    assert_eq!(info.requests_total, 2);
    assert!(
        info.latency_ms >= 1,
        "expected latency_ms updated via ping/pong, got {}",
        info.latency_ms
    );

    let _ = child.kill().await;
}
