use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use futures_util::stream::{self, Stream, StreamExt};
use neruton_proto::{
    DeleteTunnelResponse, ErrorResponse, HealthResponse, LogsResponse, ServerEvent, ServerInfo,
    TunnelsResponse,
};
use serde::Deserialize;
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    pub token: Option<String>,
}

pub async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(state.health())
}

pub async fn info_handler(State(state): State<Arc<AppState>>) -> Json<ServerInfo> {
    Json(state.server_info())
}

pub async fn list_tunnels_handler(State(state): State<Arc<AppState>>) -> Json<TunnelsResponse> {
    Json(TunnelsResponse {
        tunnels: state.list_tunnels(),
    })
}

pub async fn get_tunnel_handler(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Response {
    match state.get_tunnel(&prefix) {
        Some(tunnel) => Json(tunnel.to_info()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("tunnel '{prefix}' not found"),
            }),
        )
            .into_response(),
    }
}

pub async fn delete_tunnel_handler(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
    headers: HeaderMap,
    Query(query): Query<TokenQuery>,
) -> Response {
    if !state.is_authorized(&headers, query.token.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "unauthorized: invalid or missing auth token".to_string(),
            }),
        )
            .into_response();
    }

    match state.disconnect_tunnel(&prefix) {
        Some(tunnel) => Json(DeleteTunnelResponse {
            ok: true,
            prefix: tunnel.prefix.clone(),
        })
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("tunnel '{prefix}' not found"),
            }),
        )
            .into_response(),
    }
}

pub async fn tunnel_logs_handler(
    State(state): State<Arc<AppState>>,
    Path(prefix): Path<String>,
) -> Response {
    match state.get_tunnel(&prefix) {
        Some(tunnel) => Json(LogsResponse {
            logs: tunnel.recent_logs(),
        })
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("tunnel '{prefix}' not found"),
            }),
        )
            .into_response(),
    }
}

pub async fn global_logs_handler(State(state): State<Arc<AppState>>) -> Json<LogsResponse> {
    Json(LogsResponse {
        logs: state.global_logs(),
    })
}

pub async fn events_sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events_tx.subscribe();
    let event_stream = BroadcastStream::new(rx).filter_map(|item| async move {
        match item {
            Ok(ev) => serde_json::to_string(&ev)
                .ok()
                .map(|json| Ok(Event::default().data(json))),
            Err(_) => None,
        }
    });

    let heartbeat_state = state.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let heartbeat_stream = IntervalStream::new(interval).filter_map(move |_| {
        let ev = ServerEvent::Heartbeat {
            timestamp: Utc::now().to_rfc3339(),
            active_tunnels: heartbeat_state.tunnels.len(),
            total_requests: heartbeat_state.total_requests.load(Ordering::Relaxed),
        };
        let encoded = serde_json::to_string(&ev)
            .ok()
            .map(|json| Ok(Event::default().data(json)));
        async move { encoded }
    });

    let combined = stream::select(event_stream, heartbeat_stream);
    Sse::new(combined).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}
