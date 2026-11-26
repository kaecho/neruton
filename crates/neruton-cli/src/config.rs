use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CliConfig {
    pub server: Option<String>,
    pub token: Option<String>,
}

pub fn default_config_path() -> PathBuf {
    #[cfg(unix)]
    if let Some(home) = dirs::home_dir() {
        return home.join(".config").join("neruton").join("config.toml");
    }

    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("neruton")
        .join("config.toml")
}

pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_path)
}

pub fn load_config(explicit: Option<&Path>) -> Result<CliConfig> {
    let path = resolve_config_path(explicit);
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    let cfg: CliConfig = toml::from_str(&content)
        .with_context(|| format!("failed to parse TOML config {}", path.display()))?;
    Ok(cfg)
}

pub fn save_config(explicit: Option<&Path>, cfg: &CliConfig) -> Result<PathBuf> {
    let path = resolve_config_path(explicit);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    }
    let content = toml::to_string_pretty(cfg).context("failed to serialize config TOML")?;
    fs::write(&path, content)
        .with_context(|| format!("failed to write config file {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }

    Ok(path)
}
