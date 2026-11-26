use std::path::PathBuf;

use clap::{ArgAction, Parser};
use neruton_proto::{
    DEFAULT_BASE_DOMAIN, DEFAULT_PANEL_HOST, DEFAULT_PUBLIC_SCHEME, RESERVED_PREFIXES,
};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "neruton-server",
    version,
    about = "Neruton edge HTTP/WS gateway and intranet tunnel relay"
)]
pub struct ServerConfig {
    /// Listen address (host:port)
    #[arg(long, env = "NERUTON_BIND", default_value = "0.0.0.0:8080")]
    pub bind: String,

    /// Base domain for wildcard tunnel subdomains (e.g. moer.eu.org)
    #[arg(
        long,
        env = "NERUTON_BASE_DOMAIN",
        default_value = DEFAULT_BASE_DOMAIN
    )]
    pub base_domain: String,

    /// Hostname serving the management panel and API (e.g. neruton.moer.eu.org)
    #[arg(long, env = "NERUTON_PANEL_HOST", default_value = DEFAULT_PANEL_HOST)]
    pub panel_host: String,

    /// Optional upstream URL for the Next.js web panel (e.g. http://neruton-web:3000)
    #[arg(long, env = "NERUTON_WEB_UPSTREAM")]
    pub web_upstream: Option<String>,

    /// Optional legacy/master Bearer auth token for tunnel connections
    #[arg(long, env = "NERUTON_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Public URL scheme advertised to clients (http or https)
    #[arg(
        long,
        env = "NERUTON_PUBLIC_SCHEME",
        default_value = DEFAULT_PUBLIC_SCHEME
    )]
    pub public_scheme: String,

    /// Directory for persisted state (`state.json`)
    #[arg(long, env = "NERUTON_DATA_DIR", default_value = "./data")]
    pub data_dir: PathBuf,

    /// Initial value of `require_tunnel_auth` when creating fresh state (default: true)
    #[arg(
        long,
        env = "NERUTON_REQUIRE_AUTH",
        default_value_t = true,
        action = ArgAction::Set
    )]
    pub require_auth: bool,

    /// Initial admin username used when seeding with NERUTON_ADMIN_PASSWORD
    #[arg(long, env = "NERUTON_ADMIN_USER", default_value = "admin")]
    pub admin_user: String,

    /// Optional initial admin password; if set and 0 users exist, seeds admin + initial CLI token
    #[arg(long, env = "NERUTON_ADMIN_PASSWORD")]
    pub admin_password: Option<String>,

    /// Optional HMAC secret for signing session cookies (auto-generated and persisted if unset)
    #[arg(long, env = "NERUTON_SESSION_SECRET")]
    pub session_secret: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8080".to_string(),
            base_domain: DEFAULT_BASE_DOMAIN.to_string(),
            panel_host: DEFAULT_PANEL_HOST.to_string(),
            web_upstream: None,
            auth_token: None,
            public_scheme: DEFAULT_PUBLIC_SCHEME.to_string(),
            data_dir: PathBuf::from("./data"),
            require_auth: true,
            admin_user: "admin".to_string(),
            admin_password: None,
            session_secret: None,
        }
    }
}

impl ServerConfig {
    pub fn base_domain(&self) -> String {
        self.base_domain
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase()
    }

    pub fn panel_host(&self) -> String {
        self.panel_host
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase()
    }

    pub fn public_scheme(&self) -> String {
        let s = self.public_scheme.trim().to_ascii_lowercase();
        if s.is_empty() {
            DEFAULT_PUBLIC_SCHEME.to_string()
        } else {
            s
        }
    }

    pub fn auth_token(&self) -> Option<&str> {
        self.auth_token
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    pub fn web_upstream(&self) -> Option<&str> {
        self.web_upstream
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    pub fn admin_user(&self) -> &str {
        let trimmed = self.admin_user.trim();
        if trimmed.is_empty() {
            "admin"
        } else {
            trimmed
        }
    }

    pub fn admin_password(&self) -> Option<&str> {
        self.admin_password.as_deref().filter(|s| !s.is_empty())
    }

    pub fn session_secret(&self) -> Option<&str> {
        self.session_secret
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }

    /// If `panel_host` is a subdomain of `base_domain`, returns its label so clients cannot register it.
    pub fn panel_subdomain_label(&self) -> Option<String> {
        let panel = self.panel_host();
        let suffix = format!(".{}", self.base_domain());
        panel.strip_suffix(&suffix).map(str::to_string)
    }

    /// Built-in reserved prefixes plus panel subdomain label (if distinct).
    pub fn default_reserved_prefixes(&self) -> Vec<String> {
        let mut list: Vec<String> = RESERVED_PREFIXES.iter().map(|s| (*s).to_string()).collect();
        if let Some(panel) = self.panel_subdomain_label() {
            if !list.iter().any(|p| p == &panel) {
                list.push(panel);
            }
        }
        list
    }

    pub fn public_url(&self, prefix: &str) -> String {
        format!("{}://{prefix}.{}", self.public_scheme(), self.base_domain())
    }

    pub fn path_url(&self, prefix: &str) -> String {
        format!(
            "{}://{}/t/{prefix}/",
            self.public_scheme(),
            self.panel_host()
        )
    }

    pub fn preview_url(&self, prefix: &str) -> String {
        format!(
            "{}://{}/preview/{prefix}",
            self.public_scheme(),
            self.panel_host()
        )
    }

    pub fn dashboard_url(&self) -> String {
        format!("{}://{}/", self.public_scheme(), self.panel_host())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_require_auth_boolean_values() {
        let default_cfg = ServerConfig::try_parse_from(["neruton-server"]).unwrap();
        assert!(default_cfg.require_auth);
        assert_eq!(default_cfg.data_dir, PathBuf::from("./data"));
        assert_eq!(default_cfg.admin_user, "admin");

        let off_cfg =
            ServerConfig::try_parse_from(["neruton-server", "--require-auth", "false"]).unwrap();
        assert!(!off_cfg.require_auth);

        let on_cfg =
            ServerConfig::try_parse_from(["neruton-server", "--require-auth", "true"]).unwrap();
        assert!(on_cfg.require_auth);
    }
}
