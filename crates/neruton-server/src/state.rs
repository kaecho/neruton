use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use anyhow::Result;
use dashmap::{DashMap, DashSet};
use http::HeaderMap;
use neruton_proto::{
    HealthResponse, RequestLog, ServerEvent, ServerInfo, SettingsResponse, TunnelInfo, YamuxClient,
    VERSION,
};
use tokio::sync::broadcast;

use crate::auth::{extract_cookie, SESSION_COOKIE_NAME};
use crate::config::ServerConfig;
use crate::store::{StateStore, UserRecord};

pub const MAX_LOGS: usize = 200;

#[derive(Debug, Clone)]
pub struct LoggedRequest {
    pub owner_id: Option<String>,
    pub log: RequestLog,
}

#[derive(Debug, Clone)]
pub struct InternalEvent {
    pub owner_id: Option<String>,
    pub event: ServerEvent,
}

pub struct ActiveTunnel {
    pub id: String,
    pub prefix: String,
    pub public_url: String,
    pub path_url: String,
    pub preview_url: String,
    pub target_url: String,
    pub client_version: String,
    pub client_os: String,
    pub remote_addr: String,
    pub connected_at: String,
    pub owner_id: Option<String>,
    pub owner_username: Option<String>,
    pub token_id: Option<String>,
    pub token_name: Option<String>,
    pub requests_total: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub active_streams: AtomicU64,
    pub latency_ms: Arc<AtomicU64>,
    pub disconnected_emitted: AtomicBool,
    pub yamux: YamuxClient,
    logs: RwLock<VecDeque<RequestLog>>,
}

impl ActiveTunnel {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        prefix: String,
        public_url: String,
        path_url: String,
        preview_url: String,
        target_url: String,
        client_version: String,
        client_os: String,
        remote_addr: String,
        connected_at: String,
        owner_id: Option<String>,
        owner_username: Option<String>,
        token_id: Option<String>,
        token_name: Option<String>,
        latency_ms: Arc<AtomicU64>,
        yamux: YamuxClient,
    ) -> Self {
        Self {
            id,
            prefix,
            public_url,
            path_url,
            preview_url,
            target_url,
            client_version,
            client_os,
            remote_addr,
            connected_at,
            owner_id,
            owner_username,
            token_id,
            token_name,
            requests_total: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            active_streams: AtomicU64::new(0),
            latency_ms,
            disconnected_emitted: AtomicBool::new(false),
            yamux,
            logs: RwLock::new(VecDeque::with_capacity(MAX_LOGS)),
        }
    }

    pub fn to_info(&self) -> TunnelInfo {
        TunnelInfo {
            id: self.id.clone(),
            prefix: self.prefix.clone(),
            public_url: self.public_url.clone(),
            path_url: self.path_url.clone(),
            preview_url: self.preview_url.clone(),
            target_url: self.target_url.clone(),
            client_version: self.client_version.clone(),
            client_os: self.client_os.clone(),
            remote_addr: self.remote_addr.clone(),
            connected_at: self.connected_at.clone(),
            requests_total: self.requests_total.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            active_streams: self.active_streams.load(Ordering::Relaxed),
            latency_ms: self.latency_ms.load(Ordering::Relaxed),
            status: "online".to_string(),
            owner_id: self.owner_id.clone(),
            owner_username: self.owner_username.clone(),
            token_id: self.token_id.clone(),
            token_name: self.token_name.clone(),
        }
    }

    pub fn push_log(&self, log: RequestLog) {
        if let Ok(mut guard) = self.logs.write() {
            guard.push_front(log);
            guard.truncate(MAX_LOGS);
        }
    }

    pub fn clear_logs(&self) {
        if let Ok(mut guard) = self.logs.write() {
            guard.clear();
        }
    }

    pub fn recent_logs(&self) -> Vec<RequestLog> {
        self.logs
            .read()
            .map(|guard| guard.iter().cloned().collect())
            .unwrap_or_default()
    }
}

pub struct AppState {
    pub config: ServerConfig,
    pub store: StateStore,
    pub started_at: Instant,
    pub tunnels: DashMap<String, Arc<ActiveTunnel>>,
    pub reserved_prefixes: DashSet<String>,
    pub user_tunnel_slots: Mutex<HashMap<String, usize>>,
    global_logs: RwLock<VecDeque<LoggedRequest>>,
    pub total_requests: AtomicU64,
    pub events_tx: broadcast::Sender<InternalEvent>,
}

impl AppState {
    pub fn new(config: ServerConfig) -> Result<Arc<Self>> {
        let store = StateStore::load_or_init(&config)?;
        let (events_tx, _) = broadcast::channel(512);
        Ok(Arc::new(Self {
            config,
            store,
            started_at: Instant::now(),
            tunnels: DashMap::new(),
            reserved_prefixes: DashSet::new(),
            user_tunnel_slots: Mutex::new(HashMap::new()),
            global_logs: RwLock::new(VecDeque::with_capacity(MAX_LOGS)),
            total_requests: AtomicU64::new(0),
            events_tx,
        }))
    }

    /// Normalize a `Host` header value by stripping port, trimming whitespace/trailing dots,
    /// and lowercasing.
    pub fn normalize_host(raw: &str) -> String {
        let trimmed = raw.trim();
        // Handle IPv6 bracket notation `[::1]:8080`
        let without_port = if trimmed.starts_with('[') {
            if let Some(end) = trimmed.find(']') {
                &trimmed[..=end]
            } else {
                trimmed
            }
        } else if let Some((host, _port)) = trimmed.rsplit_once(':') {
            host
        } else {
            trimmed
        };
        without_port.trim_end_matches('.').to_ascii_lowercase()
    }

    /// If `normalized_host` is a wildcard subdomain under `NERUTON_BASE_DOMAIN` and NOT
    /// `NERUTON_PANEL_HOST`, returns `Some(prefix)`.
    pub fn extract_wildcard_prefix(&self, normalized_host: &str) -> Option<String> {
        let panel_host = self.config.panel_host();
        if normalized_host == panel_host {
            return None;
        }
        let suffix = format!(".{}", self.config.base_domain());
        let prefix = normalized_host.strip_suffix(&suffix)?;
        if prefix.is_empty() {
            return None;
        }
        Some(prefix.to_string())
    }

    /// Verify incoming `neruton_session` cookie against persisted users & `token_version`.
    pub fn authenticate_session(&self, headers: &HeaderMap) -> Option<UserRecord> {
        let cookie_val = extract_cookie(headers, SESSION_COOKIE_NAME)?;
        self.store.verify_session_cookie(&cookie_val)
    }

    /// Acquire a per-user quota slot if `max_tunnels_per_user > 0`.
    pub fn try_acquire_user_slot(&self, owner_id: &str, max_tunnels: u32) -> bool {
        let Ok(mut slots) = self.user_tunnel_slots.lock() else {
            return false;
        };
        let current = slots.get(owner_id).copied().unwrap_or(0);
        if max_tunnels > 0 && current >= max_tunnels as usize {
            return false;
        }
        slots.insert(owner_id.to_string(), current + 1);
        true
    }

    /// Release a previously acquired per-user quota slot.
    pub fn release_user_slot(&self, owner_id: &str) {
        if let Ok(mut slots) = self.user_tunnel_slots.lock() {
            if let Some(count) = slots.get_mut(owner_id) {
                if *count <= 1 {
                    slots.remove(owner_id);
                } else {
                    *count -= 1;
                }
            }
        }
    }

    /// All dynamic extra reserved prefixes (panel subdomain label + persisted custom prefixes).
    pub fn extra_reserved_prefixes(&self) -> Vec<String> {
        let mut list = self.store.settings().reserved_prefixes;
        if let Some(panel) = self.config.panel_subdomain_label() {
            if !list.iter().any(|p| p == &panel) {
                list.push(panel);
            }
        }
        list
    }

    pub fn emit_event(&self, owner_id: Option<String>, event: ServerEvent) {
        let _ = self.events_tx.send(InternalEvent { owner_id, event });
    }

    pub fn record_request(&self, tunnel: &ActiveTunnel, log: RequestLog) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        tunnel.requests_total.fetch_add(1, Ordering::Relaxed);
        tunnel.bytes_in.fetch_add(log.bytes_in, Ordering::Relaxed);
        tunnel.bytes_out.fetch_add(log.bytes_out, Ordering::Relaxed);
        tunnel.push_log(log.clone());
        if let Ok(mut guard) = self.global_logs.write() {
            guard.push_front(LoggedRequest {
                owner_id: tunnel.owner_id.clone(),
                log: log.clone(),
            });
            guard.truncate(MAX_LOGS);
        }
        self.emit_event(tunnel.owner_id.clone(), ServerEvent::RequestLogged { log });
    }

    pub fn global_logs_for(&self, requester: &UserRecord) -> Vec<RequestLog> {
        self.global_logs
            .read()
            .map(|guard| {
                guard
                    .iter()
                    .filter(|entry| {
                        requester.role.is_admin()
                            || entry.owner_id.as_deref() == Some(requester.id.as_str())
                    })
                    .map(|entry| entry.log.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn clear_all_logs(&self) {
        if let Ok(mut guard) = self.global_logs.write() {
            guard.clear();
        }
        for entry in self.tunnels.iter() {
            entry.value().clear_logs();
        }
    }

    pub fn list_tunnels_for(&self, requester: &UserRecord) -> Vec<TunnelInfo> {
        let mut items: Vec<TunnelInfo> = self
            .tunnels
            .iter()
            .filter(|e| {
                requester.role.is_admin()
                    || e.value().owner_id.as_deref() == Some(requester.id.as_str())
            })
            .map(|e| e.value().to_info())
            .collect();
        items.sort_by(|a, b| b.connected_at.cmp(&a.connected_at));
        items
    }

    pub fn active_tunnel_counts_by_user(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for entry in self.tunnels.iter() {
            if let Some(owner_id) = &entry.value().owner_id {
                *counts.entry(owner_id.clone()).or_insert(0) += 1;
            }
        }
        counts
    }

    pub fn active_tunnel_count_for_user(&self, user_id: &str) -> usize {
        self.tunnels
            .iter()
            .filter(|e| e.value().owner_id.as_deref() == Some(user_id))
            .count()
    }

    pub fn get_tunnel(&self, prefix: &str) -> Option<Arc<ActiveTunnel>> {
        let key = prefix.trim().to_ascii_lowercase();
        self.tunnels.get(&key).map(|e| e.value().clone())
    }

    /// Force-disconnect an active tunnel (used by `DELETE /_neruton/api/tunnels/:prefix` and revocations).
    pub fn disconnect_tunnel(&self, prefix: &str) -> Option<Arc<ActiveTunnel>> {
        let key = prefix.trim().to_ascii_lowercase();
        let (_, tunnel) = self.tunnels.remove(&key)?;
        tunnel.yamux.close();
        if !tunnel.disconnected_emitted.swap(true, Ordering::SeqCst) {
            self.emit_event(
                tunnel.owner_id.clone(),
                ServerEvent::TunnelDisconnected {
                    prefix: tunnel.prefix.clone(),
                    tunnel_id: tunnel.id.clone(),
                },
            );
        }
        Some(tunnel)
    }

    /// Immediately disconnect all active tunnels authenticated with `token_id`.
    pub fn disconnect_tunnels_by_token(&self, token_id: &str) -> usize {
        let prefixes: Vec<String> = self
            .tunnels
            .iter()
            .filter(|e| e.value().token_id.as_deref() == Some(token_id))
            .map(|e| e.key().clone())
            .collect();
        let mut count = 0;
        for prefix in prefixes {
            if self.disconnect_tunnel(&prefix).is_some() {
                count += 1;
            }
        }
        count
    }

    /// Immediately disconnect active tunnels using `token_id` whose prefix is not in `allowed_prefixes`.
    pub fn disconnect_tunnels_violating_allowed_prefixes(
        &self,
        token_id: &str,
        allowed_prefixes: &[String],
    ) -> usize {
        if allowed_prefixes.is_empty() {
            return 0;
        }
        let prefixes: Vec<String> = self
            .tunnels
            .iter()
            .filter(|e| {
                e.value().token_id.as_deref() == Some(token_id)
                    && !allowed_prefixes.iter().any(|p| p == &e.value().prefix)
            })
            .map(|e| e.key().clone())
            .collect();
        let mut count = 0;
        for prefix in prefixes {
            if self.disconnect_tunnel(&prefix).is_some() {
                count += 1;
            }
        }
        count
    }

    /// Immediately disconnect all active tunnels owned by `owner_id`.
    pub fn disconnect_tunnels_by_owner(&self, owner_id: &str) -> usize {
        let prefixes: Vec<String> = self
            .tunnels
            .iter()
            .filter(|e| e.value().owner_id.as_deref() == Some(owner_id))
            .map(|e| e.key().clone())
            .collect();
        let mut count = 0;
        for prefix in prefixes {
            if self.disconnect_tunnel(&prefix).is_some() {
                count += 1;
            }
        }
        count
    }

    /// Remove tunnel upon natural WebSocket termination (guarded by `tunnel_id` to prevent races).
    pub fn cleanup_tunnel(&self, prefix: &str, tunnel_id: &str) {
        let removed = self
            .tunnels
            .remove_if(prefix, |_, existing| existing.id == tunnel_id);
        if let Some((_, tunnel)) = removed {
            if !tunnel.disconnected_emitted.swap(true, Ordering::SeqCst) {
                self.emit_event(
                    tunnel.owner_id.clone(),
                    ServerEvent::TunnelDisconnected {
                        prefix: tunnel.prefix.clone(),
                        tunnel_id: tunnel.id.clone(),
                    },
                );
            }
        }
    }

    pub fn health(&self) -> HealthResponse {
        HealthResponse {
            status: "ok".to_string(),
            version: VERSION.to_string(),
            base_domain: self.config.base_domain(),
            panel_host: self.config.panel_host(),
            auth_required: self.store.require_tunnel_auth(),
            active_tunnels: self.tunnels.len(),
        }
    }

    pub fn settings_response(&self) -> SettingsResponse {
        let settings = self.store.settings();
        SettingsResponse {
            require_tunnel_auth: settings.require_tunnel_auth,
            max_tunnels_per_user: settings.max_tunnels_per_user,
            reserved_prefixes: settings.reserved_prefixes,
            default_reserved_prefixes: self.config.default_reserved_prefixes(),
            env_token_configured: self.config.auth_token().is_some(),
        }
    }

    pub fn server_info_for(&self, requester: Option<&UserRecord>) -> ServerInfo {
        let require_tunnel_auth = self.store.require_tunnel_auth();
        let (total_users, total_tokens) = self.store.counts_for(requester);
        let (active_tunnels, total_requests) = match requester {
            Some(user) if !user.role.is_admin() => {
                let mut active = 0usize;
                let mut reqs = 0u64;
                for entry in self.tunnels.iter() {
                    if entry.value().owner_id.as_deref() == Some(user.id.as_str()) {
                        active += 1;
                        reqs += entry.value().requests_total.load(Ordering::Relaxed);
                    }
                }
                (active, reqs)
            }
            _ => (
                self.tunnels.len(),
                self.total_requests.load(Ordering::Relaxed),
            ),
        };

        ServerInfo {
            version: VERSION.to_string(),
            base_domain: self.config.base_domain(),
            panel_host: self.config.panel_host(),
            public_scheme: self.config.public_scheme(),
            require_tunnel_auth,
            auth_required: require_tunnel_auth,
            uptime_secs: self.started_at.elapsed().as_secs(),
            active_tunnels,
            total_requests,
            total_users,
            total_tokens,
        }
    }
}
