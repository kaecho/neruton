use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use axum::http::Method;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get};
use axum::{Json, Router};
use tower_http::cors::{Any, CorsLayer};

use crate::api::{
    delete_tunnel_handler, events_sse_handler, get_tunnel_handler, global_logs_handler,
    health_handler, info_handler, list_tunnels_handler, tunnel_logs_handler,
};
use crate::proxy::{proxy_to_tunnel, proxy_to_web_upstream, tunnel_offline_response};
use crate::state::AppState;
use crate::tunnel_ws::ws_tunnel_handler;

pub fn build_app(state: Arc<AppState>) -> Router {
    let api_cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);

    let api_router = Router::new()
        .route("/info", get(info_handler))
        .route("/tunnels", get(list_tunnels_handler))
        .route("/tunnels/{prefix}", get(get_tunnel_handler))
        .route("/tunnels/{prefix}", delete(delete_tunnel_handler))
        .route("/tunnels/{prefix}/logs", get(tunnel_logs_handler))
        .route("/logs", get(global_logs_handler))
        .route("/events", get(events_sse_handler))
        .layer(api_cors);

    let panel_router = Router::new()
        .route("/_neruton/health", get(health_handler))
        .route("/_neruton/tunnel", get(ws_tunnel_handler))
        .nest("/_neruton/api", api_router)
        .route("/t/{prefix}", any(path_proxy_root_handler))
        .route("/t/{prefix}/", any(path_proxy_root_handler))
        .route("/t/{prefix}/{*rest}", any(path_proxy_rest_handler))
        .fallback(panel_fallback_handler)
        .with_state(state.clone());

    panel_router.layer(middleware::from_fn_with_state(
        state,
        wildcard_host_middleware,
    ))
}

fn extract_request_host(req: &Request<Body>) -> String {
    if let Some(h) = req
        .headers()
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
    {
        return h.to_string();
    }
    req.uri()
        .authority()
        .map(|a| a.as_str().to_string())
        .unwrap_or_default()
}

fn extract_client_ip(req: &Request<Body>) -> String {
    if let Some(ip) = req
        .headers()
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return ip.to_string();
    }
    if let Some(ip) = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return ip.to_string();
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn wildcard_host_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let raw_host = extract_request_host(&req);
    let normalized_host = AppState::normalize_host(&raw_host);

    if let Some(prefix) = state.extract_wildcard_prefix(&normalized_host) {
        let client_ip = extract_client_ip(&req);
        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        return match state.get_tunnel(&prefix) {
            Some(tunnel) => {
                proxy_to_tunnel(
                    state,
                    tunnel,
                    req,
                    "subdomain",
                    path_and_query,
                    client_ip,
                    raw_host,
                    false,
                )
                .await
            }
            None => tunnel_offline_response(&state, &prefix),
        };
    }

    next.run(req).await
}

async fn path_proxy_root_handler(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    req: Request<Body>,
) -> Response {
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let target_path = format!("/{query}");
    handle_path_proxy(state, prefix, target_path, req).await
}

async fn path_proxy_rest_handler(
    State(state): State<Arc<AppState>>,
    Path((prefix, rest)): Path<(String, String)>,
    req: Request<Body>,
) -> Response {
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let clean_rest = rest.trim_start_matches('/');
    let target_path = format!("/{clean_rest}{query}");
    handle_path_proxy(state, prefix, target_path, req).await
}

async fn handle_path_proxy(
    state: Arc<AppState>,
    prefix: String,
    target_path: String,
    req: Request<Body>,
) -> Response {
    let raw_host = extract_request_host(&req);
    let client_ip = extract_client_ip(&req);
    match state.get_tunnel(&prefix) {
        Some(tunnel) => {
            proxy_to_tunnel(
                state,
                tunnel,
                req,
                "path",
                target_path,
                client_ip,
                raw_host,
                true,
            )
            .await
        }
        None => tunnel_offline_response(&state, &prefix),
    }
}

async fn panel_fallback_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    if let Some(upstream) = state.config.web_upstream() {
        let raw_host = extract_request_host(&req);
        let client_ip = extract_client_ip(&req);
        return proxy_to_web_upstream(
            upstream,
            req,
            client_ip,
            raw_host,
            &state.config.public_scheme(),
        )
        .await;
    }

    Json(state.server_info()).into_response()
}
