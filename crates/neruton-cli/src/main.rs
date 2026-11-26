mod config;
mod forwarder;
mod tls;
mod tunnel;
mod ui;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use neruton_proto::{DEFAULT_PANEL_HOST, VERSION};
use tracing_subscriber::EnvFilter;

use crate::config::{load_config, resolve_config_path, save_config};
use crate::tunnel::{run_tunnel_loop, TunnelOptions};

const DEFAULT_SERVER_URL: &str = "https://neruton.moer.eu.org";

#[derive(Debug, Parser)]
#[command(
    name = "neruton",
    version = VERSION,
    about = "Self-hosted intranet penetration & wildcard tunnel client inspired by cloudflared",
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start an HTTP/WebSocket tunnel forwarding to a local service
    Tunnel(TunnelArgs),

    /// Shorthand for `neruton tunnel --url <PORT_OR_URL>` (e.g. `neruton http 3000`)
    Http(HttpArgs),

    /// Manage persistent CLI configuration (~/.config/neruton/config.toml)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Print version and build metadata
    Version,
}

#[derive(Debug, Args)]
struct CommonTunnelFlags {
    /// Neruton gateway server URL (env: NERUTON_SERVER, default: https://neruton.moer.eu.org)
    #[arg(long, env = "NERUTON_SERVER")]
    server: Option<String>,

    /// Custom subdomain prefix (auto-generates a UUID v4 if omitted)
    #[arg(short = 's', long = "subdomain", visible_alias = "prefix")]
    subdomain: Option<String>,

    /// Optional Bearer auth token for protected servers (env: NERUTON_TOKEN)
    #[arg(long, env = "NERUTON_TOKEN")]
    token: Option<String>,

    /// Disable TLS certificate verification for self-signed servers or local HTTPS targets
    #[arg(long)]
    no_tls_verify: bool,

    /// Control the Host header sent to the local service (`preserve`, or a custom host value)
    #[arg(long)]
    host_header: Option<String>,

    /// Path to config file (default: ~/.config/neruton/config.toml)
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct TunnelArgs {
    /// Local target URL or port to expose (e.g. http://localhost:3000 or 3000)
    #[arg(short = 'u', long = "url")]
    url: String,

    #[command(flatten)]
    common: CommonTunnelFlags,
}

#[derive(Debug, Args)]
struct HttpArgs {
    /// Local port or URL (e.g. `3000`, `localhost:8080`, or `http://127.0.0.1:3000`)
    target: String,

    #[command(flatten)]
    common: CommonTunnelFlags,
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Save default server URL and/or auth token to config.toml
    Set {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show the current resolved configuration
    Show {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

fn resolve_server_and_token(common: &CommonTunnelFlags) -> Result<(String, Option<String>)> {
    let file_cfg = load_config(common.config.as_deref())?;

    let server = common
        .server
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| file_cfg.server.filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());

    let token = common
        .token
        .clone()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("NERUTON_AUTH_TOKEN")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| file_cfg.token.filter(|s| !s.trim().is_empty()));

    Ok((server, token))
}

#[tokio::main]
async fn main() -> Result<()> {
    tls::install_crypto_provider();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Tunnel(args) => {
            let (server, token) = resolve_server_and_token(&args.common)?;
            run_tunnel_loop(TunnelOptions {
                server,
                target_url: args.url,
                subdomain: args.common.subdomain,
                token,
                no_tls_verify: args.common.no_tls_verify,
                host_header: args.common.host_header,
            })
            .await
        }
        Commands::Http(args) => {
            let (server, token) = resolve_server_and_token(&args.common)?;
            run_tunnel_loop(TunnelOptions {
                server,
                target_url: args.target,
                subdomain: args.common.subdomain,
                token,
                no_tls_verify: args.common.no_tls_verify,
                host_header: args.common.host_header,
            })
            .await
        }
        Commands::Config { action } => match action {
            ConfigAction::Set {
                server,
                token,
                config,
            } => {
                if server.is_none() && token.is_none() {
                    anyhow::bail!("provide at least one of --server or --token");
                }
                let mut cfg = load_config(config.as_deref())?;
                if let Some(s) = server {
                    cfg.server = if s.trim().is_empty() { None } else { Some(s) };
                }
                if let Some(t) = token {
                    cfg.token = if t.trim().is_empty() { None } else { Some(t) };
                }
                let saved = save_config(config.as_deref(), &cfg)?;
                println!("Saved configuration to {}", saved.display());
                Ok(())
            }
            ConfigAction::Show { config } => {
                let path = resolve_config_path(config.as_deref());
                let cfg = load_config(config.as_deref())?;
                let effective_server = std::env::var("NERUTON_SERVER")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| cfg.server.clone())
                    .unwrap_or_else(|| format!("https://{DEFAULT_PANEL_HOST}"));
                let token_status = if cfg.token.as_deref().is_some_and(|s| !s.is_empty()) {
                    "<configured>"
                } else {
                    "<not set>"
                };
                println!("Config file:      {}", path.display());
                println!("Effective server: {effective_server}");
                println!(
                    "Saved server:     {}",
                    cfg.server.as_deref().unwrap_or("<default>")
                );
                println!("Saved token:      {token_status}");
                Ok(())
            }
        },
        Commands::Version => {
            println!(
                "neruton {VERSION} ({}/{})",
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tunnel_and_http_subcommands() {
        let cli = Cli::try_parse_from([
            "neruton",
            "tunnel",
            "--url",
            "http://localhost:3000",
            "--server",
            "https://neruton.moer.eu.org",
            "-s",
            "my-app",
            "--token",
            "tok123",
            "--no-tls-verify",
            "--host-header",
            "preserve",
        ])
        .unwrap();
        match cli.command {
            Commands::Tunnel(args) => {
                assert_eq!(args.url, "http://localhost:3000");
                assert_eq!(
                    args.common.server.as_deref(),
                    Some("https://neruton.moer.eu.org")
                );
                assert_eq!(args.common.subdomain.as_deref(), Some("my-app"));
                assert_eq!(args.common.token.as_deref(), Some("tok123"));
                assert!(args.common.no_tls_verify);
                assert_eq!(args.common.host_header.as_deref(), Some("preserve"));
            }
            _ => panic!("expected Tunnel command"),
        }

        let http_cli =
            Cli::try_parse_from(["neruton", "http", "3000", "--prefix", "quick-demo"]).unwrap();
        match http_cli.command {
            Commands::Http(args) => {
                assert_eq!(args.target, "3000");
                assert_eq!(args.common.subdomain.as_deref(), Some("quick-demo"));
            }
            _ => panic!("expected Http command"),
        }
    }
}
