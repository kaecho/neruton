use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{Context, Result};
use chrono::Utc;
use neruton_proto::{
    validate_prefix, validate_prefix_format, validate_username, TokenCreatedResponse, TokenSummary,
    UpdateSettingsRequest, UserAdminView, UserPublic, UserRole,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{
    constant_time_eq, generate_session_secret, generate_tunnel_token, hash_password_sync,
    sha256_hex, sign_session, verify_session, SessionPayload, SESSION_MAX_AGE_SECS,
};
use crate::config::ServerConfig;

const STATE_FILE_NAME: &str = "state.json";
const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub session_secret: String,
    pub settings: SystemSettings,
    #[serde(default)]
    pub users: Vec<UserRecord>,
    #[serde(default)]
    pub tokens: Vec<TokenRecord>,
}

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSettings {
    #[serde(default = "default_require_tunnel_auth")]
    pub require_tunnel_auth: bool,
    #[serde(default)]
    pub max_tunnels_per_user: u32,
    #[serde(default)]
    pub reserved_prefixes: Vec<String>,
}

fn default_require_tunnel_auth() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub role: UserRole,
    pub enabled: bool,
    pub token_version: u64,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

impl UserRecord {
    pub fn to_public(&self) -> UserPublic {
        UserPublic {
            id: self.id.clone(),
            username: self.username.clone(),
            role: self.role,
            enabled: self.enabled,
            created_at: self.created_at.clone(),
            last_login_at: self.last_login_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub name: String,
    pub token_prefix: String,
    pub token_hash: String,
    pub owner_id: String,
    pub enabled: bool,
    #[serde(default)]
    pub allowed_prefixes: Vec<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TunnelTokenMatch {
    pub owner_id: String,
    pub owner_username: String,
    pub token_id: String,
    pub token_name: String,
    pub allowed_prefixes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("persistence error: {0}")]
    Internal(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelTokenError {
    #[error("Tunnel token is disabled.")]
    TokenDisabled,
    #[error("Account owning this tunnel token is disabled.")]
    OwnerDisabled,
}

pub struct StateStore {
    data_dir: PathBuf,
    state_path: PathBuf,
    session_secret_override: Option<String>,
    inner: RwLock<PersistedState>,
}

impl StateStore {
    pub fn load_or_init(config: &ServerConfig) -> Result<Self> {
        let data_dir = config.data_dir.clone();
        fs::create_dir_all(&data_dir).with_context(|| {
            format!("failed to create NERUTON_DATA_DIR '{}'", data_dir.display())
        })?;
        let state_path = data_dir.join(STATE_FILE_NAME);
        let session_secret_override = config.session_secret().map(str::to_string);

        let (mut state, mut dirty) = if state_path.exists() {
            let bytes = fs::read(&state_path)
                .with_context(|| format!("failed to read state file '{}'", state_path.display()))?;
            let parsed: PersistedState = serde_json::from_slice(&bytes).with_context(|| {
                format!("failed to parse state file '{}'", state_path.display())
            })?;
            (parsed, false)
        } else {
            let initial = PersistedState {
                schema_version: CURRENT_SCHEMA_VERSION,
                session_secret: generate_session_secret(),
                settings: SystemSettings {
                    require_tunnel_auth: config.require_auth,
                    max_tunnels_per_user: 0,
                    reserved_prefixes: Vec::new(),
                },
                users: Vec::new(),
                tokens: Vec::new(),
            };
            (initial, true)
        };

        if state.session_secret.trim().is_empty() {
            state.session_secret = generate_session_secret();
            dirty = true;
        }

        // Seed initial admin user + default CLI token if configured via env and 0 users exist.
        if state.users.is_empty() {
            if let Some(admin_pw) = config.admin_password() {
                let username = validate_username(config.admin_user())
                    .map_err(|e| anyhow::anyhow!("invalid NERUTON_ADMIN_USER: {e}"))?;
                if admin_pw.chars().count() < 8 {
                    warn!(
                        username = %username,
                        "NERUTON_ADMIN_PASSWORD is shorter than 8 characters; consider using a stronger password"
                    );
                }
                let password_hash = hash_password_sync(admin_pw)?;
                let now = Utc::now().to_rfc3339();
                let user_id = Uuid::new_v4().to_string();
                let user = UserRecord {
                    id: user_id.clone(),
                    username: username.clone(),
                    password_hash,
                    role: UserRole::Admin,
                    enabled: true,
                    token_version: 1,
                    created_at: now.clone(),
                    last_login_at: None,
                };
                let (_secret, token_prefix, token_hash) = generate_tunnel_token();
                let token = TokenRecord {
                    id: Uuid::new_v4().to_string(),
                    name: "Default CLI Token".to_string(),
                    token_prefix: token_prefix.clone(),
                    token_hash,
                    owner_id: user_id,
                    enabled: true,
                    allowed_prefixes: Vec::new(),
                    created_at: now,
                    last_used_at: None,
                };
                state.users.push(user);
                state.tokens.push(token);
                dirty = true;
                info!(
                    username = %username,
                    token_prefix = %token_prefix,
                    "seeded initial admin account and default tunnel token from environment"
                );
            }
        }

        let store = Self {
            data_dir,
            state_path,
            session_secret_override,
            inner: RwLock::new(state),
        };

        if dirty {
            let guard = store
                .inner
                .read()
                .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
            store.write_atomic(&guard)?;
        }

        Ok(store)
    }

    fn write_atomic(&self, state: &PersistedState) -> Result<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        let tmp_name = format!(".{STATE_FILE_NAME}.tmp.{}", Uuid::new_v4());
        let tmp_path = self.data_dir.join(tmp_name);

        let write_result = (|| -> Result<()> {
            let mut file = File::create(&tmp_path).with_context(|| {
                format!("failed to create temp state file '{}'", tmp_path.display())
            })?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
            }

            file.write_all(&payload)?;
            file.sync_all()?;
            drop(file);

            fs::rename(&tmp_path, &self.state_path).with_context(|| {
                format!(
                    "failed to replace state file '{}'",
                    self.state_path.display()
                )
            })?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }

        write_result
    }

    fn persist(&self, state: &PersistedState) -> Result<(), StoreError> {
        self.write_atomic(state)
            .map_err(|e| StoreError::Internal(e.to_string()))
    }

    fn session_secret_from(&self, state: &PersistedState) -> String {
        self.session_secret_override
            .clone()
            .unwrap_or_else(|| state.session_secret.clone())
    }

    pub fn needs_setup(&self) -> bool {
        self.inner
            .read()
            .map(|g| g.users.is_empty())
            .unwrap_or(false)
    }

    pub fn settings(&self) -> SystemSettings {
        self.inner
            .read()
            .map(|g| g.settings.clone())
            .unwrap_or(SystemSettings {
                require_tunnel_auth: true,
                max_tunnels_per_user: 0,
                reserved_prefixes: Vec::new(),
            })
    }

    pub fn require_tunnel_auth(&self) -> bool {
        self.settings().require_tunnel_auth
    }

    pub fn counts_for(&self, requester: Option<&UserRecord>) -> (usize, usize) {
        let Ok(guard) = self.inner.read() else {
            return (0, 0);
        };
        match requester {
            Some(user) if !user.role.is_admin() => {
                let own_tokens = guard
                    .tokens
                    .iter()
                    .filter(|t| t.owner_id == user.id)
                    .count();
                (1, own_tokens)
            }
            _ => (guard.users.len(), guard.tokens.len()),
        }
    }

    pub fn issue_session_token(&self, user: &UserRecord) -> Result<String, StoreError> {
        let guard = self
            .inner
            .read()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;
        let secret = self.session_secret_from(&guard);
        let payload = SessionPayload {
            uid: user.id.clone(),
            username: user.username.clone(),
            role: user.role,
            exp: Utc::now().timestamp() + SESSION_MAX_AGE_SECS,
            token_version: user.token_version,
        };
        sign_session(&secret, &payload).map_err(|e| StoreError::Internal(e.to_string()))
    }

    pub fn verify_session_cookie(&self, cookie_val: &str) -> Option<UserRecord> {
        let guard = self.inner.read().ok()?;
        let secret = self.session_secret_from(&guard);
        let payload = verify_session(&secret, cookie_val)?;
        let user = guard.users.iter().find(|u| u.id == payload.uid)?;
        if !user.enabled || user.token_version != payload.token_version {
            return None;
        }
        Some(user.clone())
    }

    pub fn setup_initial_admin(
        &self,
        username: String,
        password_hash: String,
    ) -> Result<(UserRecord, TokenCreatedResponse), StoreError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        if !guard.users.is_empty() {
            return Err(StoreError::Conflict(
                "initial setup has already been completed".to_string(),
            ));
        }

        let now = Utc::now().to_rfc3339();
        let user = UserRecord {
            id: Uuid::new_v4().to_string(),
            username: username.clone(),
            password_hash,
            role: UserRole::Admin,
            enabled: true,
            token_version: 1,
            created_at: now.clone(),
            last_login_at: Some(now.clone()),
        };

        let (secret, token_prefix, token_hash) = generate_tunnel_token();
        let token = TokenRecord {
            id: Uuid::new_v4().to_string(),
            name: "Default CLI Token".to_string(),
            token_prefix,
            token_hash,
            owner_id: user.id.clone(),
            enabled: true,
            allowed_prefixes: Vec::new(),
            created_at: now,
            last_used_at: None,
        };

        let token_summary = token_to_summary(&token, &username);
        guard.users.push(user.clone());
        guard.tokens.push(token);
        self.persist(&guard)?;

        Ok((
            user,
            TokenCreatedResponse {
                token: token_summary,
                secret,
            },
        ))
    }

    pub fn find_user_by_username(&self, username: &str) -> Option<UserRecord> {
        let needle = username.trim().to_ascii_lowercase();
        let guard = self.inner.read().ok()?;
        guard
            .users
            .iter()
            .find(|u| u.username.to_ascii_lowercase() == needle)
            .cloned()
    }

    pub fn record_login(&self, user_id: &str) -> Result<UserRecord, StoreError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;
        let user = guard
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or_else(|| StoreError::NotFound("user not found".to_string()))?;
        user.last_login_at = Some(Utc::now().to_rfc3339());
        let updated = user.clone();
        self.persist(&guard)?;
        Ok(updated)
    }

    pub fn change_password(
        &self,
        user_id: &str,
        new_password_hash: String,
    ) -> Result<UserRecord, StoreError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;
        let user = guard
            .users
            .iter_mut()
            .find(|u| u.id == user_id)
            .ok_or_else(|| StoreError::NotFound("user not found".to_string()))?;
        user.password_hash = new_password_hash;
        user.token_version = user.token_version.saturating_add(1);
        let updated = user.clone();
        self.persist(&guard)?;
        Ok(updated)
    }

    pub fn list_tokens(&self, requester: &UserRecord) -> Vec<TokenSummary> {
        let Ok(guard) = self.inner.read() else {
            return Vec::new();
        };
        let usernames: HashMap<&str, &str> = guard
            .users
            .iter()
            .map(|u| (u.id.as_str(), u.username.as_str()))
            .collect();

        let mut list: Vec<TokenSummary> = guard
            .tokens
            .iter()
            .filter(|t| requester.role.is_admin() || t.owner_id == requester.id)
            .map(|t| {
                let owner_name = usernames
                    .get(t.owner_id.as_str())
                    .copied()
                    .unwrap_or("unknown");
                token_to_summary(t, owner_name)
            })
            .collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list
    }

    pub fn create_token(
        &self,
        owner: &UserRecord,
        raw_name: &str,
        allowed_prefixes: Option<Vec<String>>,
    ) -> Result<TokenCreatedResponse, StoreError> {
        let name = validate_token_name(raw_name)?;
        let normalized_prefixes = normalize_allowed_prefixes(allowed_prefixes.unwrap_or_default())?;

        let (secret, token_prefix, token_hash) = generate_tunnel_token();
        let token = TokenRecord {
            id: Uuid::new_v4().to_string(),
            name,
            token_prefix,
            token_hash,
            owner_id: owner.id.clone(),
            enabled: true,
            allowed_prefixes: normalized_prefixes,
            created_at: Utc::now().to_rfc3339(),
            last_used_at: None,
        };

        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        let summary = token_to_summary(&token, &owner.username);
        guard.tokens.push(token);
        self.persist(&guard)?;

        Ok(TokenCreatedResponse {
            token: summary,
            secret,
        })
    }

    pub fn update_token(
        &self,
        requester: &UserRecord,
        token_id: &str,
        name: Option<String>,
        enabled: Option<bool>,
        allowed_prefixes: Option<Vec<String>>,
    ) -> Result<(TokenSummary, bool), StoreError> {
        let validated_name = match name {
            Some(n) => Some(validate_token_name(&n)?),
            None => None,
        };
        let validated_prefixes = match allowed_prefixes {
            Some(p) => Some(normalize_allowed_prefixes(p)?),
            None => None,
        };

        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        let idx = guard
            .tokens
            .iter()
            .position(|t| t.id == token_id)
            .ok_or_else(|| StoreError::NotFound(format!("token '{token_id}' not found")))?;

        if !requester.role.is_admin() && guard.tokens[idx].owner_id != requester.id {
            return Err(StoreError::Forbidden(
                "cannot modify another user's token".to_string(),
            ));
        }

        let mut became_disabled = false;
        if let Some(n) = validated_name {
            guard.tokens[idx].name = n;
        }
        if let Some(en) = enabled {
            if !en {
                became_disabled = true;
            }
            guard.tokens[idx].enabled = en;
        }
        if let Some(prefixes) = validated_prefixes {
            guard.tokens[idx].allowed_prefixes = prefixes;
        }

        let owner_id = guard.tokens[idx].owner_id.clone();
        let owner_name = guard
            .users
            .iter()
            .find(|u| u.id == owner_id)
            .map(|u| u.username.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let summary = token_to_summary(&guard.tokens[idx], &owner_name);
        self.persist(&guard)?;

        Ok((summary, became_disabled))
    }

    pub fn delete_token(&self, requester: &UserRecord, token_id: &str) -> Result<(), StoreError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        let idx = guard
            .tokens
            .iter()
            .position(|t| t.id == token_id)
            .ok_or_else(|| StoreError::NotFound(format!("token '{token_id}' not found")))?;

        if !requester.role.is_admin() && guard.tokens[idx].owner_id != requester.id {
            return Err(StoreError::Forbidden(
                "cannot delete another user's token".to_string(),
            ));
        }

        guard.tokens.remove(idx);
        self.persist(&guard)?;
        Ok(())
    }

    /// Authenticate a user-issued tunnel token by SHA-256 digest and update `last_used_at`.
    pub fn authenticate_tunnel_token(
        &self,
        raw_token: &str,
    ) -> Result<Option<TunnelTokenMatch>, TunnelTokenError> {
        let candidate_hash = sha256_hex(raw_token);
        let mut guard = match self.inner.write() {
            Ok(g) => g,
            Err(_) => return Ok(None),
        };

        let Some(token_idx) = guard
            .tokens
            .iter()
            .position(|t| constant_time_eq(t.token_hash.as_bytes(), candidate_hash.as_bytes()))
        else {
            return Ok(None);
        };

        if !guard.tokens[token_idx].enabled {
            return Err(TunnelTokenError::TokenDisabled);
        }

        let owner_id = guard.tokens[token_idx].owner_id.clone();
        let Some(owner) = guard.users.iter().find(|u| u.id == owner_id) else {
            return Err(TunnelTokenError::OwnerDisabled);
        };
        if !owner.enabled {
            return Err(TunnelTokenError::OwnerDisabled);
        }
        let owner_username = owner.username.clone();

        guard.tokens[token_idx].last_used_at = Some(Utc::now().to_rfc3339());
        let matched = TunnelTokenMatch {
            owner_id,
            owner_username,
            token_id: guard.tokens[token_idx].id.clone(),
            token_name: guard.tokens[token_idx].name.clone(),
            allowed_prefixes: guard.tokens[token_idx].allowed_prefixes.clone(),
        };

        if let Err(e) = self.write_atomic(&guard) {
            warn!(error = %e, "failed persisting token last_used_at");
        }

        Ok(Some(matched))
    }

    pub fn list_users(
        &self,
        active_tunnels_by_user: &HashMap<String, usize>,
    ) -> Vec<UserAdminView> {
        let Ok(guard) = self.inner.read() else {
            return Vec::new();
        };

        let mut token_counts: HashMap<&str, usize> = HashMap::new();
        for tok in &guard.tokens {
            *token_counts.entry(tok.owner_id.as_str()).or_insert(0) += 1;
        }

        let mut list: Vec<UserAdminView> = guard
            .users
            .iter()
            .map(|u| UserAdminView {
                user: u.to_public(),
                token_count: token_counts.get(u.id.as_str()).copied().unwrap_or(0),
                active_tunnel_count: active_tunnels_by_user.get(&u.id).copied().unwrap_or(0),
            })
            .collect();
        list.sort_by(|a, b| a.user.created_at.cmp(&b.user.created_at));
        list
    }

    pub fn create_user(
        &self,
        username: String,
        password_hash: String,
        role: UserRole,
    ) -> Result<UserAdminView, StoreError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        let lower = username.to_ascii_lowercase();
        if guard
            .users
            .iter()
            .any(|u| u.username.to_ascii_lowercase() == lower)
        {
            return Err(StoreError::Conflict(format!(
                "username '{username}' already exists"
            )));
        }

        let user = UserRecord {
            id: Uuid::new_v4().to_string(),
            username,
            password_hash,
            role,
            enabled: true,
            token_version: 1,
            created_at: Utc::now().to_rfc3339(),
            last_login_at: None,
        };
        let view = UserAdminView {
            user: user.to_public(),
            token_count: 0,
            active_tunnel_count: 0,
        };

        guard.users.push(user);
        self.persist(&guard)?;
        Ok(view)
    }

    pub fn update_user(
        &self,
        user_id: &str,
        role: Option<UserRole>,
        enabled: Option<bool>,
        new_password_hash: Option<String>,
        active_tunnel_count: usize,
    ) -> Result<(UserAdminView, bool), StoreError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        let idx = guard
            .users
            .iter()
            .position(|u| u.id == user_id)
            .ok_or_else(|| StoreError::NotFound(format!("user '{user_id}' not found")))?;

        let current_role = guard.users[idx].role;
        let current_enabled = guard.users[idx].enabled;
        let next_role = role.unwrap_or(current_role);
        let next_enabled = enabled.unwrap_or(current_enabled);

        // Prevent disabling or demoting the last enabled admin.
        let currently_enabled_admin = current_role.is_admin() && current_enabled;
        let will_be_enabled_admin = next_role.is_admin() && next_enabled;
        if currently_enabled_admin && !will_be_enabled_admin {
            let other_enabled_admins = guard
                .users
                .iter()
                .filter(|u| u.id != user_id && u.role.is_admin() && u.enabled)
                .count();
            if other_enabled_admins == 0 {
                return Err(StoreError::BadRequest(
                    "cannot disable or demote the last enabled admin".to_string(),
                ));
            }
        }

        let mut should_bump_version = false;
        let mut became_disabled = false;

        if let Some(r) = role {
            guard.users[idx].role = r;
        }
        if let Some(en) = enabled {
            if !en {
                became_disabled = true;
                should_bump_version = true;
            }
            guard.users[idx].enabled = en;
        }
        if let Some(hash) = new_password_hash {
            guard.users[idx].password_hash = hash;
            should_bump_version = true;
        }
        if should_bump_version {
            guard.users[idx].token_version = guard.users[idx].token_version.saturating_add(1);
        }

        let token_count = guard
            .tokens
            .iter()
            .filter(|t| t.owner_id == user_id)
            .count();
        let view = UserAdminView {
            user: guard.users[idx].to_public(),
            token_count,
            active_tunnel_count: if became_disabled {
                0
            } else {
                active_tunnel_count
            },
        };

        self.persist(&guard)?;
        Ok((view, became_disabled))
    }

    pub fn delete_user(&self, requester_id: &str, user_id: &str) -> Result<(), StoreError> {
        if requester_id == user_id {
            return Err(StoreError::BadRequest(
                "cannot delete your own account".to_string(),
            ));
        }

        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        let idx = guard
            .users
            .iter()
            .position(|u| u.id == user_id)
            .ok_or_else(|| StoreError::NotFound(format!("user '{user_id}' not found")))?;

        let target = &guard.users[idx];
        if target.role.is_admin() && target.enabled {
            let other_enabled_admins = guard
                .users
                .iter()
                .filter(|u| u.id != user_id && u.role.is_admin() && u.enabled)
                .count();
            if other_enabled_admins == 0 {
                return Err(StoreError::BadRequest(
                    "cannot delete the last enabled admin".to_string(),
                ));
            }
        }

        guard.users.remove(idx);
        guard.tokens.retain(|t| t.owner_id != user_id);
        self.persist(&guard)?;
        Ok(())
    }

    pub fn update_settings(
        &self,
        req: UpdateSettingsRequest,
    ) -> Result<SystemSettings, StoreError> {
        let normalized_reserved = match req.reserved_prefixes {
            Some(list) => Some(normalize_reserved_prefixes(list)?),
            None => None,
        };

        let mut guard = self
            .inner
            .write()
            .map_err(|_| StoreError::Internal("state lock poisoned".to_string()))?;

        if let Some(require) = req.require_tunnel_auth {
            guard.settings.require_tunnel_auth = require;
        }
        if let Some(max) = req.max_tunnels_per_user {
            guard.settings.max_tunnels_per_user = max;
        }
        if let Some(reserved) = normalized_reserved {
            guard.settings.reserved_prefixes = reserved;
        }

        let updated = guard.settings.clone();
        self.persist(&guard)?;
        Ok(updated)
    }
}

fn token_to_summary(token: &TokenRecord, owner_username: &str) -> TokenSummary {
    TokenSummary {
        id: token.id.clone(),
        name: token.name.clone(),
        token_prefix: token.token_prefix.clone(),
        owner_id: token.owner_id.clone(),
        owner_username: owner_username.to_string(),
        enabled: token.enabled,
        allowed_prefixes: token.allowed_prefixes.clone(),
        created_at: token.created_at.clone(),
        last_used_at: token.last_used_at.clone(),
    }
}

fn validate_token_name(raw: &str) -> Result<String, StoreError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(StoreError::BadRequest(
            "token name cannot be empty".to_string(),
        ));
    }
    if trimmed.chars().count() > 64 {
        return Err(StoreError::BadRequest(
            "token name must be at most 64 characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}

fn normalize_allowed_prefixes(raw: Vec<String>) -> Result<Vec<String>, StoreError> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in raw {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let valid = validate_prefix(trimmed).map_err(|e| StoreError::BadRequest(e.to_string()))?;
        if seen.insert(valid.clone()) {
            out.push(valid);
        }
    }
    Ok(out)
}

fn normalize_reserved_prefixes(raw: Vec<String>) -> Result<Vec<String>, StoreError> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in raw {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let valid =
            validate_prefix_format(trimmed).map_err(|e| StoreError::BadRequest(e.to_string()))?;
        if seen.insert(valid.clone()) {
            out.push(valid);
        }
    }
    Ok(out)
}
