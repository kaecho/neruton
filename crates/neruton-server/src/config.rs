use clap::Parser;
use neruton_proto::{DEFAULT_BASE_DOMAIN, DEFAULT_PANEL_HOST, DEFAULT_PUBLIC_SCHEME};

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

    /// Optional Bearer auth token for tunnel registration & tunnel disconnect API
    #[arg(long, env = "NERUTON_AUTH_TOKEN")]
    pub auth_token: Option<String>,

    /// Public URL scheme advertised to clients (http or https)
    #[arg(
        long,
        env = "NERUTON_PUBLIC_SCHEME",
        default_value = DEFAULT_PUBLIC_SCHEME
    )]
    pub public_scheme: String,
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

    /// If `panel_host` is a subdomain of `base_domain`, returns its label so clients cannot register it.
    pub fn panel_subdomain_label(&self) -> Option<String> {
        let panel = self.panel_host();
        let suffix = format!(".{}", self.base_domain());
        panel.strip_suffix(&suffix).map(str::to_string)
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
