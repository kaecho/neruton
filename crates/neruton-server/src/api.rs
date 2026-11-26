use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{FromRequestParts, Path, State};
use axum::http::header::{self, HeaderValue};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use futures_util::stream::{self, Stream, StreamExt};
use neruton_proto::{
    validate_password, validate_username, AuthStatusResponse, AuthUserResponse,
    ChangePasswordRequest, CreateTokenRequest, CreateUserRequest, DeleteTunnelResponse,
    ErrorResponse, HealthResponse, LoginRequest, LogsResponse, OkResponse, ServerEvent, ServerInfo,
    SettingsResponse, SetupRequest, SetupResponse, TokenResponse, TokensResponse, TunnelsResponse,
    UpdateSettingsRequest, UpdateTokenRequest, UpdateUserRequest, UserResponse, UsersResponse,
    VERSION,
};
use tokio_stream::wrappers::{BroadcastStream, IntervalStream};

use crate::auth::{
    build_clear_session_cookie, build_session_cookie, hash_password, should_set_secure_cookie,
    verify_password,
};
use crate::state::AppState;
use crate::store::{StoreError, UserRecord};

/// Extractor requiring a valid `neruton_session` cookie.
pub struct AuthenticatedUser(pub UserRecord);

impl FromRequestParts<Arc<AppState>> for AuthenticatedUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        match state.authenticate_session(&parts.headers) {
            Some(user) => Ok(Self(user)),
            None => Err(error_response(StatusCode::UNAUTHORIZED, "unauthorized")),
        }
    }
}

/// Extractor requiring a valid `neruton_session` cookie belonging to an `admin` user.
pub struct AdminUser(pub UserRecord);

impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let AuthenticatedUser(user) = AuthenticatedUser::from_request_parts(parts, state).await?;
        if !user.role.is_admin() {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                "admin privileges required",
            ));
        }
        Ok(Self(user))
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

impl IntoResponse for StoreError {
    fn into_response(self) -> Response {
        let status = match self {
            StoreError::BadRequest(_) => StatusCode::BAD_REQUEST,
            StoreError::Conflict(_) => StatusCode::CONFLICT,
            StoreError::Forbidden(_) => StatusCode::FORBIDDEN,
            StoreError::NotFound(_) => StatusCode::NOT_FOUND,
            StoreError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        error_response(status, self.to_string())
    }
}

fn session_cookie_header(
    state: &AppState,
    req_headers: &HeaderMap,
    user: &UserRecord,
) -> Result<HeaderValue, StoreError> {
    let signed = state.store.issue_session_token(user)?;
    let secure = should_set_secure_cookie(&state.config.public_scheme(), req_headers);
    let cookie = build_session_cookie(&signed, secure);
    HeaderValue::from_str(&cookie).map_err(|e| StoreError::Internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------

pub async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(state.health())
}

pub async fn auth_status_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<AuthStatusResponse> {
    let needs_setup = state.store.needs_setup();
    let user = state.authenticate_session(&headers).map(|u| u.to_public());
    Json(AuthStatusResponse {
        needs_setup,
        authenticated: user.is_some(),
        user,
        panel_host: state.config.panel_host(),
        base_domain: state.config.base_domain(),
        public_scheme: state.config.public_scheme(),
        version: VERSION.to_string(),
    })
}

pub async fn auth_setup_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SetupRequest>,
) -> Response {
    if !state.store.needs_setup() {
        return error_response(
            StatusCode::CONFLICT,
            "initial setup has already been completed",
        );
    }

    let username = match validate_username(&req.username) {
        Ok(u) => u,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    if let Err(msg) = validate_password(&req.password) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }

    let password_hash = match hash_password(req.password).await {
        Ok(h) => h,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let (user, initial_token) = match state.store.setup_initial_admin(username, password_hash) {
        Ok(pair) => pair,
        Err(err) => return err.into_response(),
    };

    let cookie_hv = match session_cookie_header(&state, &headers, &user) {
        Ok(hv) => hv,
        Err(err) => return err.into_response(),
    };

    (
        StatusCode::CREATED,
        [(header::SET_COOKIE, cookie_hv)],
        Json(SetupResponse {
            user: user.to_public(),
            initial_token,
        }),
    )
        .into_response()
}

pub async fn auth_login_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Response {
    let Some(user) = state.store.find_user_by_username(&req.username) else {
        return error_response(StatusCode::UNAUTHORIZED, "invalid username or password");
    };

    let valid = verify_password(req.password, user.password_hash.clone()).await;
    if !valid {
        return error_response(StatusCode::UNAUTHORIZED, "invalid username or password");
    }

    if !user.enabled {
        return error_response(StatusCode::UNAUTHORIZED, "account is disabled");
    }

    let updated = match state.store.record_login(&user.id) {
        Ok(u) => u,
        Err(err) => return err.into_response(),
    };

    let cookie_hv = match session_cookie_header(&state, &headers, &updated) {
        Ok(hv) => hv,
        Err(err) => return err.into_response(),
    };

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie_hv)],
        Json(AuthUserResponse {
            user: updated.to_public(),
        }),
    )
        .into_response()
}

pub async fn auth_logout_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Response {
    let secure = should_set_secure_cookie(&state.config.public_scheme(), &headers);
    let clear = build_clear_session_cookie(secure);
    let Ok(cookie_hv) = HeaderValue::from_str(&clear) else {
        return Json(OkResponse { ok: true }).into_response();
    };
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie_hv)],
        Json(OkResponse { ok: true }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Authenticated account endpoints
// ---------------------------------------------------------------------------

pub async fn auth_me_handler(AuthenticatedUser(user): AuthenticatedUser) -> Json<AuthUserResponse> {
    Json(AuthUserResponse {
        user: user.to_public(),
    })
}

pub async fn auth_password_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Response {
    if let Err(msg) = validate_password(&req.new_password) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }

    let valid = verify_password(req.current_password, user.password_hash.clone()).await;
    if !valid {
        return error_response(StatusCode::BAD_REQUEST, "current password is incorrect");
    }

    let new_hash = match hash_password(req.new_password).await {
        Ok(h) => h,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let updated = match state.store.change_password(&user.id, new_hash) {
        Ok(u) => u,
        Err(err) => return err.into_response(),
    };

    let cookie_hv = match session_cookie_header(&state, &headers, &updated) {
        Ok(hv) => hv,
        Err(err) => return err.into_response(),
    };

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie_hv)],
        Json(OkResponse { ok: true }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Info, Tunnels, Logs, SSE
// ---------------------------------------------------------------------------

pub async fn info_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Json<ServerInfo> {
    Json(state.server_info_for(Some(&user)))
}

pub async fn list_tunnels_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Json<TunnelsResponse> {
    Json(TunnelsResponse {
        tunnels: state.list_tunnels_for(&user),
    })
}

pub async fn get_tunnel_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(prefix): Path<String>,
) -> Response {
    let Some(tunnel) = state.get_tunnel(&prefix) else {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("tunnel '{prefix}' not found"),
        );
    };
    if !user.role.is_admin() && tunnel.owner_id.as_deref() != Some(user.id.as_str()) {
        return error_response(StatusCode::FORBIDDEN, "forbidden");
    }
    Json(tunnel.to_info()).into_response()
}

pub async fn delete_tunnel_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(prefix): Path<String>,
) -> Response {
    let Some(tunnel) = state.get_tunnel(&prefix) else {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("tunnel '{prefix}' not found"),
        );
    };
    if !user.role.is_admin() && tunnel.owner_id.as_deref() != Some(user.id.as_str()) {
        return error_response(StatusCode::FORBIDDEN, "forbidden");
    }

    match state.disconnect_tunnel(&prefix) {
        Some(removed) => Json(DeleteTunnelResponse {
            ok: true,
            prefix: removed.prefix.clone(),
        })
        .into_response(),
        None => error_response(
            StatusCode::NOT_FOUND,
            format!("tunnel '{prefix}' not found"),
        ),
    }
}

pub async fn tunnel_logs_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(prefix): Path<String>,
) -> Response {
    let Some(tunnel) = state.get_tunnel(&prefix) else {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("tunnel '{prefix}' not found"),
        );
    };
    if !user.role.is_admin() && tunnel.owner_id.as_deref() != Some(user.id.as_str()) {
        return error_response(StatusCode::FORBIDDEN, "forbidden");
    }
    Json(LogsResponse {
        logs: tunnel.recent_logs(),
    })
    .into_response()
}

pub async fn global_logs_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Json<LogsResponse> {
    Json(LogsResponse {
        logs: state.global_logs_for(&user),
    })
}

pub async fn clear_logs_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(_admin): AdminUser,
) -> Json<OkResponse> {
    state.clear_all_logs();
    Json(OkResponse { ok: true })
}

pub async fn events_sse_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events_tx.subscribe();
    let is_admin = user.role.is_admin();
    let user_id = user.id.clone();

    let event_stream = BroadcastStream::new(rx).filter_map(move |item| {
        let user_id = user_id.clone();
        async move {
            match item {
                Ok(internal) => {
                    if !is_admin && internal.owner_id.as_deref() != Some(user_id.as_str()) {
                        return None;
                    }
                    serde_json::to_string(&internal.event)
                        .ok()
                        .map(|json| Ok(Event::default().data(json)))
                }
                Err(_) => None,
            }
        }
    });

    let heartbeat_state = state.clone();
    let hb_user_id = user.id.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let heartbeat_stream = IntervalStream::new(interval).filter_map(move |_| {
        let (active_tunnels, total_requests) = if is_admin {
            (
                heartbeat_state.tunnels.len(),
                heartbeat_state.total_requests.load(Ordering::Relaxed),
            )
        } else {
            let mut active = 0usize;
            let mut reqs = 0u64;
            for entry in heartbeat_state.tunnels.iter() {
                if entry.value().owner_id.as_deref() == Some(hb_user_id.as_str()) {
                    active += 1;
                    reqs += entry.value().requests_total.load(Ordering::Relaxed);
                }
            }
            (active, reqs)
        };
        let ev = ServerEvent::Heartbeat {
            timestamp: Utc::now().to_rfc3339(),
            active_tunnels,
            total_requests,
        };
        let encoded = serde_json::to_string(&ev)
            .ok()
            .map(|json| Ok(Event::default().data(json)));
        async move { encoded }
    });

    let combined = stream::select(event_stream, heartbeat_stream);
    Sse::new(combined).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}

// ---------------------------------------------------------------------------
// Tunnel Tokens
// ---------------------------------------------------------------------------

pub async fn list_tokens_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Json<TokensResponse> {
    Json(TokensResponse {
        tokens: state.store.list_tokens(&user),
    })
}

pub async fn create_token_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(req): Json<CreateTokenRequest>,
) -> Response {
    match state
        .store
        .create_token(&user, &req.name, req.allowed_prefixes)
    {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(err) => err.into_response(),
    }
}

pub async fn update_token_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateTokenRequest>,
) -> Response {
    match state
        .store
        .update_token(&user, &id, req.name, req.enabled, req.allowed_prefixes)
    {
        Ok((summary, became_disabled)) => {
            if became_disabled {
                state.disconnect_tunnels_by_token(&id);
            } else if !summary.allowed_prefixes.is_empty() {
                state.disconnect_tunnels_violating_allowed_prefixes(&id, &summary.allowed_prefixes);
            }
            Json(TokenResponse { token: summary }).into_response()
        }
        Err(err) => err.into_response(),
    }
}

pub async fn delete_token_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<String>,
) -> Response {
    match state.store.delete_token(&user, &id) {
        Ok(()) => {
            state.disconnect_tunnels_by_token(&id);
            Json(OkResponse { ok: true }).into_response()
        }
        Err(err) => err.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Users (Admin only)
// ---------------------------------------------------------------------------

pub async fn list_users_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(_admin): AdminUser,
) -> Json<UsersResponse> {
    let counts = state.active_tunnel_counts_by_user();
    Json(UsersResponse {
        users: state.store.list_users(&counts),
    })
}

pub async fn create_user_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(_admin): AdminUser,
    Json(req): Json<CreateUserRequest>,
) -> Response {
    let username = match validate_username(&req.username) {
        Ok(u) => u,
        Err(msg) => return error_response(StatusCode::BAD_REQUEST, msg),
    };
    if let Err(msg) = validate_password(&req.password) {
        return error_response(StatusCode::BAD_REQUEST, msg);
    }

    let password_hash = match hash_password(req.password).await {
        Ok(h) => h,
        Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    match state.store.create_user(username, password_hash, req.role) {
        Ok(view) => (StatusCode::CREATED, Json(UserResponse { user: view })).into_response(),
        Err(err) => err.into_response(),
    }
}

pub async fn update_user_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(_admin): AdminUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Response {
    let new_password_hash = match req.password {
        Some(pw) => {
            if let Err(msg) = validate_password(&pw) {
                return error_response(StatusCode::BAD_REQUEST, msg);
            }
            match hash_password(pw).await {
                Ok(h) => Some(h),
                Err(e) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            }
        }
        None => None,
    };

    let active_count = state.active_tunnel_count_for_user(&id);
    match state
        .store
        .update_user(&id, req.role, req.enabled, new_password_hash, active_count)
    {
        Ok((view, became_disabled)) => {
            if became_disabled {
                state.disconnect_tunnels_by_owner(&id);
            }
            Json(UserResponse { user: view }).into_response()
        }
        Err(err) => err.into_response(),
    }
}

pub async fn delete_user_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(admin): AdminUser,
    Path(id): Path<String>,
) -> Response {
    match state.store.delete_user(&admin.id, &id) {
        Ok(()) => {
            state.disconnect_tunnels_by_owner(&id);
            Json(OkResponse { ok: true }).into_response()
        }
        Err(err) => err.into_response(),
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

pub async fn get_settings_handler(
    State(state): State<Arc<AppState>>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Json<SettingsResponse> {
    Json(state.settings_response())
}

pub async fn update_settings_handler(
    State(state): State<Arc<AppState>>,
    AdminUser(_admin): AdminUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> Response {
    match state.store.update_settings(req) {
        Ok(_) => Json(state.settings_response()).into_response(),
        Err(err) => err.into_response(),
    }
}
