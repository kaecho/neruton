mod config;
mod doh;
mod forwarder;
mod hpke;
mod tls;
mod tunnel;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use neruton_proto::{DEFAULT_PANEL_HOST, VERSION};
use tracing_subscriber::EnvFilter;

use crate::config::{load_config, resolve_config_path, save_config, CliConfig};
use crate::doh::DohConfig;
use crate::tls::{SniMode, StealthTlsOptions};
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

#[derive(Debug, Default, Args)]
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

    /// DNS-over-HTTPS mode or comma-separated endpoint URL(s): auto | strict | off | https://... (env: NERUTON_DOH)
    #[arg(long, value_name = "MODE_OR_URLS")]
    doh: Option<String>,

    /// Disable DNS-over-HTTPS and use system DNS (overrides NERUTON_DOH and config.toml)
    #[arg(long)]
    no_doh: bool,

    /// TLS SNI hiding mode: auto | ech | fragment | none | plain (env: NERUTON_SNI_MODE)
    #[arg(long, value_name = "MODE")]
    sni_mode: Option<String>,

    /// Custom TLS SNI hostname (cert is still verified against real server host) (env: NERUTON_SNI)
    #[arg(long, value_name = "HOST")]
    sni: Option<String>,

    /// Explicit base64-encoded TLS 1.3 ECHConfigList (env: NERUTON_ECH_CONFIG)
    #[arg(long, value_name = "BASE64")]
    ech_config: Option<String>,

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
    /// Save persistent defaults to config.toml
    Set {
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        token: Option<String>,
        #[arg(long, value_name = "MODE_OR_URLS")]
        doh: Option<String>,
        #[arg(long)]
        no_doh: bool,
        #[arg(long, value_name = "MODE")]
        sni_mode: Option<String>,
        #[arg(long, value_name = "HOST")]
        sni: Option<String>,
        #[arg(long, value_name = "BASE64")]
        ech_config: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Show the current resolved configuration
    Show {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

struct ResolvedSettings {
    server: String,
    token: Option<String>,
    doh: DohConfig,
    tls: StealthTlsOptions,
}

fn decode_ech_config_base64(raw: &str) -> Result<Vec<u8>> {
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        bail!("--ech-config value is empty");
    }
    let bytes = STANDARD
        .decode(&compact)
        .or_else(|_| STANDARD_NO_PAD.decode(&compact))
        .with_context(|| "invalid base64 in --ech-config / NERUTON_ECH_CONFIG")?;
    if bytes.is_empty() {
        bail!("decoded --ech-config is empty");
    }
    Ok(bytes)
}

fn non_empty_trimmed(opt: Option<&str>) -> Option<String> {
    opt.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_settings_with_env<F>(
    common: &CommonTunnelFlags,
    file_cfg: &CliConfig,
    env_get: F,
) -> Result<ResolvedSettings>
where
    F: Fn(&str) -> Option<String>,
{
    let env_non_empty = |key: &str| -> Option<String> {
        env_get(key)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    let server = non_empty_trimmed(common.server.as_deref())
        .or_else(|| env_non_empty("NERUTON_SERVER"))
        .or_else(|| non_empty_trimmed(file_cfg.server.as_deref()))
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());

    let token = non_empty_trimmed(common.token.as_deref())
        .or_else(|| env_non_empty("NERUTON_TOKEN"))
        .or_else(|| env_non_empty("NERUTON_AUTH_TOKEN"))
        .or_else(|| non_empty_trimmed(file_cfg.token.as_deref()));

    if common.no_doh && common.doh.is_some() {
        bail!("cannot specify both --doh and --no-doh");
    }

    let doh_raw = if common.no_doh {
        "off".to_string()
    } else {
        non_empty_trimmed(common.doh.as_deref())
            .or_else(|| env_non_empty("NERUTON_DOH"))
            .or_else(|| non_empty_trimmed(file_cfg.doh.as_deref()))
            .unwrap_or_else(|| "auto".to_string())
    };
    let doh = DohConfig::parse(&doh_raw)?;

    let sni_mode_raw = non_empty_trimmed(common.sni_mode.as_deref())
        .or_else(|| env_non_empty("NERUTON_SNI_MODE"))
        .or_else(|| non_empty_trimmed(file_cfg.sni_mode.as_deref()))
        .unwrap_or_else(|| "auto".to_string());
    let sni_mode: SniMode = sni_mode_raw.parse()?;

    let custom_sni = non_empty_trimmed(common.sni.as_deref())
        .or_else(|| env_non_empty("NERUTON_SNI"))
        .or_else(|| non_empty_trimmed(file_cfg.sni.as_deref()));

    let ech_config_b64 = non_empty_trimmed(common.ech_config.as_deref())
        .or_else(|| env_non_empty("NERUTON_ECH_CONFIG"))
        .or_else(|| non_empty_trimmed(file_cfg.ech_config.as_deref()));
    let ech_config = match ech_config_b64 {
        Some(raw) => Some(decode_ech_config_base64(&raw)?),
        None => None,
    };

    Ok(ResolvedSettings {
        server,
        token,
        doh,
        tls: StealthTlsOptions {
            sni_mode,
            custom_sni,
            ech_config,
            no_tls_verify: common.no_tls_verify,
        },
    })
}

fn resolve_settings(common: &CommonTunnelFlags) -> Result<ResolvedSettings> {
    let file_cfg = load_config(common.config.as_deref())?;
    resolve_settings_with_env(common, &file_cfg, |k| std::env::var(k).ok())
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            ui::log_error(&format!("{err:#}"));
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
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
            let resolved = resolve_settings(&args.common)?;
            run_tunnel_loop(TunnelOptions {
                server: resolved.server,
                target_url: args.url,
                subdomain: args.common.subdomain,
                token: resolved.token,
                no_tls_verify: args.common.no_tls_verify,
                host_header: args.common.host_header,
                doh: resolved.doh,
                tls: resolved.tls,
            })
            .await
        }
        Commands::Http(args) => {
            let resolved = resolve_settings(&args.common)?;
            run_tunnel_loop(TunnelOptions {
                server: resolved.server,
                target_url: args.target,
                subdomain: args.common.subdomain,
                token: resolved.token,
                no_tls_verify: args.common.no_tls_verify,
                host_header: args.common.host_header,
                doh: resolved.doh,
                tls: resolved.tls,
            })
            .await
        }
        Commands::Config { action } => match action {
            ConfigAction::Set {
                server,
                token,
                doh,
                no_doh,
                sni_mode,
                sni,
                ech_config,
                config,
            } => {
                if no_doh && doh.is_some() {
                    bail!("cannot specify both --doh and --no-doh");
                }
                if server.is_none()
                    && token.is_none()
                    && doh.is_none()
                    && !no_doh
                    && sni_mode.is_none()
                    && sni.is_none()
                    && ech_config.is_none()
                {
                    bail!("provide at least one option to set (--server, --token, --doh, --no-doh, --sni-mode, --sni, --ech-config)");
                }
                let mut cfg = load_config(config.as_deref())?;
                if let Some(s) = server {
                    cfg.server = if s.trim().is_empty() { None } else { Some(s) };
                }
                if let Some(t) = token {
                    cfg.token = if t.trim().is_empty() { None } else { Some(t) };
                }
                if no_doh {
                    cfg.doh = Some("off".to_string());
                } else if let Some(d) = doh {
                    if d.trim().is_empty() {
                        cfg.doh = None;
                    } else {
                        let parsed = DohConfig::parse(&d)?;
                        cfg.doh = Some(parsed.display_value());
                    }
                }
                if let Some(m) = sni_mode {
                    if m.trim().is_empty() {
                        cfg.sni_mode = None;
                    } else {
                        let parsed: SniMode = m.parse()?;
                        cfg.sni_mode = Some(parsed.as_str().to_string());
                    }
                }
                if let Some(host) = sni {
                    cfg.sni = if host.trim().is_empty() {
                        None
                    } else {
                        Some(host.trim().to_string())
                    };
                }
                if let Some(ech) = ech_config {
                    if ech.trim().is_empty() {
                        cfg.ech_config = None;
                    } else {
                        let _ = decode_ech_config_base64(&ech)?;
                        cfg.ech_config = Some(ech.trim().to_string());
                    }
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
                let effective_doh = std::env::var("NERUTON_DOH")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| cfg.doh.clone())
                    .unwrap_or_else(|| "auto".to_string());
                let effective_sni_mode = std::env::var("NERUTON_SNI_MODE")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| cfg.sni_mode.clone())
                    .unwrap_or_else(|| "auto".to_string());
                let effective_sni = std::env::var("NERUTON_SNI")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .or_else(|| cfg.sni.clone());
                let ech_status = if std::env::var("NERUTON_ECH_CONFIG")
                    .ok()
                    .is_some_and(|s| !s.trim().is_empty())
                    || cfg.ech_config.as_deref().is_some_and(|s| !s.is_empty())
                {
                    "<configured>"
                } else {
                    "<auto via DoH>"
                };

                println!("Config file:      {}", path.display());
                println!("Effective server: {effective_server}");
                println!(
                    "Saved server:     {}",
                    cfg.server.as_deref().unwrap_or("<default>")
                );
                println!("Saved token:      {token_status}");
                println!("Effective DoH:    {effective_doh}");
                println!(
                    "Saved DoH:        {}",
                    cfg.doh.as_deref().unwrap_or("<default: auto>")
                );
                println!(
                    "Effective SNI:    mode={effective_sni_mode}{}",
                    match effective_sni {
                        Some(ref host) => format!(", host={host}"),
                        None => String::new(),
                    }
                );
                println!(
                    "Saved SNI mode:   {}",
                    cfg.sni_mode.as_deref().unwrap_or("<default: auto>")
                );
                println!(
                    "Saved SNI host:   {}",
                    cfg.sni.as_deref().unwrap_or("<not set>")
                );
                println!("ECH config:       {ech_status}");
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
    use std::collections::HashMap;

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
            "--doh",
            "strict",
            "--sni-mode",
            "ech",
            "--sni",
            "cloudflare-ech.com",
            "--ech-config",
            "AAEC",
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
                assert_eq!(args.common.doh.as_deref(), Some("strict"));
                assert!(!args.common.no_doh);
                assert_eq!(args.common.sni_mode.as_deref(), Some("ech"));
                assert_eq!(args.common.sni.as_deref(), Some("cloudflare-ech.com"));
                assert_eq!(args.common.ech_config.as_deref(), Some("AAEC"));
            }
            _ => panic!("expected Tunnel command"),
        }

        let http_cli = Cli::try_parse_from([
            "neruton",
            "http",
            "3000",
            "--prefix",
            "quick-demo",
            "--no-doh",
            "--sni-mode",
            "fragment",
        ])
        .unwrap();
        match http_cli.command {
            Commands::Http(args) => {
                assert_eq!(args.target, "3000");
                assert_eq!(args.common.subdomain.as_deref(), Some("quick-demo"));
                assert!(args.common.no_doh);
                assert_eq!(args.common.sni_mode.as_deref(), Some("fragment"));
            }
            _ => panic!("expected Http command"),
        }
    }

    #[test]
    fn precedence_cli_over_env_over_config_over_defaults() {
        // 1. Defaults when nothing set
        let defaults =
            resolve_settings_with_env(&CommonTunnelFlags::default(), &CliConfig::default(), |_| {
                None
            })
            .unwrap();
        assert_eq!(defaults.doh, DohConfig::Auto);
        assert_eq!(defaults.tls.sni_mode, SniMode::Auto);
        assert_eq!(defaults.tls.custom_sni, None);
        assert_eq!(defaults.tls.ech_config, None);

        // 2. config.toml applies over defaults
        let file_cfg = CliConfig {
            server: Some("https://cfg.example.com".into()),
            token: Some("cfg_tok".into()),
            doh: Some("https://1.0.0.1/dns-query".into()),
            sni_mode: Some("fragment".into()),
            sni: Some("cfg-sni.example.com".into()),
            ech_config: Some("AQID".into()),
        };
        let from_cfg =
            resolve_settings_with_env(&CommonTunnelFlags::default(), &file_cfg, |_| None).unwrap();
        assert_eq!(
            from_cfg.doh,
            DohConfig::Custom(vec!["https://1.0.0.1/dns-query".into()])
        );
        assert_eq!(from_cfg.tls.sni_mode, SniMode::Fragment);
        assert_eq!(
            from_cfg.tls.custom_sni.as_deref(),
            Some("cfg-sni.example.com")
        );
        assert_eq!(from_cfg.tls.ech_config.as_deref(), Some(&[1, 2, 3][..]));

        // 3. Env overrides config.toml
        let env_map: HashMap<&str, &str> = HashMap::from([
            ("NERUTON_DOH", "strict"),
            ("NERUTON_SNI_MODE", "ech"),
            ("NERUTON_SNI", "env-sni.example.com"),
            ("NERUTON_ECH_CONFIG", "BAUG"),
        ]);
        let from_env = resolve_settings_with_env(&CommonTunnelFlags::default(), &file_cfg, |k| {
            env_map.get(k).map(|v| (*v).to_string())
        })
        .unwrap();
        assert_eq!(from_env.doh, DohConfig::Strict);
        assert_eq!(from_env.tls.sni_mode, SniMode::Ech);
        assert_eq!(
            from_env.tls.custom_sni.as_deref(),
            Some("env-sni.example.com")
        );
        assert_eq!(from_env.tls.ech_config.as_deref(), Some(&[4, 5, 6][..]));

        // 4. CLI flags (including --no-doh) override env AND config.toml
        let cli_flags = CommonTunnelFlags {
            no_doh: true,
            sni_mode: Some("none".into()),
            sni: Some("cli-sni.example.com".into()),
            ech_config: Some("BwgJ".into()),
            ..Default::default()
        };
        let from_cli = resolve_settings_with_env(&cli_flags, &file_cfg, |k| {
            env_map.get(k).map(|v| (*v).to_string())
        })
        .unwrap();
        assert_eq!(from_cli.doh, DohConfig::Off);
        assert_eq!(from_cli.tls.sni_mode, SniMode::None);
        assert_eq!(
            from_cli.tls.custom_sni.as_deref(),
            Some("cli-sni.example.com")
        );
        assert_eq!(from_cli.tls.ech_config.as_deref(), Some(&[7, 8, 9][..]));

        // 5. Specifying both --doh and --no-doh on CLI fails
        let conflict = CommonTunnelFlags {
            doh: Some("strict".into()),
            no_doh: true,
            ..Default::default()
        };
        assert!(resolve_settings_with_env(&conflict, &CliConfig::default(), |_| None).is_err());

        // 6. Invalid base64 --ech-config fails cleanly
        let bad_b64 = CommonTunnelFlags {
            ech_config: Some("!!!not-base64!!!".into()),
            ..Default::default()
        };
        assert!(resolve_settings_with_env(&bad_b64, &CliConfig::default(), |_| None).is_err());
    }
}
