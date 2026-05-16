//! Checkpoint persistence for the --resume flag.
//! Saves/loads the discovered subdomain set for a given domain to a local
//! state file so a run can be resumed without rediscovering everything.

use std::path::PathBuf;

use anyhow::Result;

pub fn state_dir() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| "C:/Windows/Temp".into());
        PathBuf::from(base).join("lancersub")
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(base).join(".local/state/lancersub")
    }
}

pub fn checkpoint_path(domain: &str) -> PathBuf {
    let safe: String = domain
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    state_dir().join(format!("{safe}.json"))
}

/// Load a previously saved checkpoint; returns empty vec if none exists.
pub fn load(domain: &str) -> Vec<String> {
    let path = checkpoint_path(domain);
    if !path.exists() {
        return Vec::new();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .unwrap_or_default()
}

/// Persist the current subdomain set to disk.
pub fn save(domain: &str, subdomains: &[String]) -> Result<()> {
    let path = checkpoint_path(domain);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(subdomains)?;
    std::fs::write(&path, content)?;
    Ok(())
}
