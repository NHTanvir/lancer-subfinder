//! Runtime config + provider (API key) config.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cli::Cli;

/// Per-source rate limit, parsed from `name=N/u` strings.
#[derive(Debug, Clone)]
pub struct RateLimitSpec {
    pub events: u32,
    pub per: Duration,
}

impl RateLimitSpec {
    pub fn parse(s: &str) -> anyhow::Result<(String, Self)> {
        let (name, rate) = s
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("rate-limit `{s}` missing '='"))?;
        let (n, unit) = rate
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("rate-limit `{s}` missing '/'"))?;
        let events: u32 = n.parse()?;
        let per = match unit {
            "s" => Duration::from_secs(1),
            "ms" => Duration::from_millis(1),
            "m" => Duration::from_secs(60),
            "h" => Duration::from_secs(3600),
            other => anyhow::bail!("rate-limit `{s}`: unknown unit `{other}`"),
        };
        Ok((name.to_ascii_lowercase(), RateLimitSpec { events, per }))
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub timeout: Duration,
    pub max_time: Duration,
    pub proxy: Option<String>,
    pub global_rate_limit: Option<u32>,
    pub rate_limits: HashMap<String, RateLimitSpec>,
    pub sources: Vec<String>,
    pub exclude_sources: Vec<String>,
    pub all_sources: bool,
    pub recursive: bool,
    pub resolvers: Vec<String>,
    pub active: bool,
    pub no_wildcard: bool,
    pub include_ip: bool,
    pub threads: usize,
    pub match_regex: Vec<String>,
    pub filter_regex: Vec<String>,
    pub exclude_ips: bool,
}

impl RuntimeConfig {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let mut rate_limits = HashMap::new();
        for r in &cli.rate_limits {
            let (k, v) = RateLimitSpec::parse(r)?;
            rate_limits.insert(k, v);
        }

        let mut resolvers = cli.resolvers.clone();
        if let Some(path) = &cli.resolver_list {
            let txt = std::fs::read_to_string(path)?;
            for line in txt.lines() {
                let l = line.trim();
                if !l.is_empty() && !l.starts_with('#') {
                    resolvers.push(l.to_string());
                }
            }
        }
        if resolvers.is_empty() {
            // canonical default set
            resolvers = vec![
                "1.1.1.1".into(),
                "8.8.8.8".into(),
                "9.9.9.9".into(),
                "208.67.222.222".into(),
            ];
        }

        let mut match_regex = cli.match_regex.clone();
        if let Some(p) = &cli.match_file {
            for line in std::fs::read_to_string(p)?.lines() {
                let l = line.trim();
                if !l.is_empty() {
                    match_regex.push(l.to_string());
                }
            }
        }
        let mut filter_regex = cli.filter_regex.clone();
        if let Some(p) = &cli.filter_file {
            for line in std::fs::read_to_string(p)?.lines() {
                let l = line.trim();
                if !l.is_empty() {
                    filter_regex.push(l.to_string());
                }
            }
        }

        Ok(RuntimeConfig {
            timeout: Duration::from_secs(cli.timeout_secs),
            max_time: Duration::from_secs(cli.max_time_mins * 60),
            proxy: cli.proxy.clone(),
            global_rate_limit: cli.rate_limit,
            rate_limits,
            sources: cli.sources.iter().map(|s| s.to_ascii_lowercase()).collect(),
            exclude_sources: cli
                .exclude_sources
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect(),
            all_sources: cli.all,
            recursive: cli.recursive,
            resolvers,
            active: cli.active || cli.no_wildcard,
            no_wildcard: cli.no_wildcard,
            include_ip: cli.include_ip,
            threads: cli.threads,
            match_regex,
            filter_regex,
            exclude_ips: cli.exclude_ips,
        })
    }
}

/// YAML provider config — per-source list of API keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(flatten)]
    pub keys: HashMap<String, Vec<String>>,
}

impl ProviderConfig {
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut cfg: ProviderConfig = match path {
            Some(p) if p.exists() => serde_yaml::from_str(&std::fs::read_to_string(p)?)?,
            _ => ProviderConfig::default(),
        };
        // overlay env vars: <SOURCE>_API_KEY (comma separated)
        for (key, val) in std::env::vars() {
            if let Some(name) = key.strip_suffix("_API_KEY") {
                let entry = cfg.keys.entry(name.to_ascii_lowercase()).or_default();
                for v in val.split(',') {
                    let v = v.trim();
                    if !v.is_empty() && !entry.iter().any(|k| k == v) {
                        entry.push(v.to_string());
                    }
                }
            }
        }
        Ok(cfg)
    }

    pub fn keys_for(&self, source: &str) -> Vec<String> {
        self.keys
            .get(&source.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}
