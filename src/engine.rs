//! Enumeration orchestrator.
//!
//! For a given target domain it:
//!  1. Picks the set of enabled sources (via Registry).
//!  2. Spawns one tokio task per source, each producing a stream of
//!     candidate subdomains into a shared `mpsc::Sender<Discovery>`.
//!  3. Drains the channel into an `IndexSet`, applying match/filter regex,
//!     IP exclusion, and (optionally) DNS active+wildcard filtering.
//!  4. Returns the final ordered set + stats.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use futures::StreamExt;
use indexmap::IndexSet;
use regex::Regex;
use tokio::sync::mpsc;

use crate::config::RuntimeConfig;
use crate::resolve::ActiveResolver;
use crate::session::Session;
use crate::sources::registry::Registry;
use crate::stats::{SourceStat, Stats};

/// One result discovered by a source.
#[derive(Debug, Clone)]
pub struct Discovery {
    pub host: String,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct SubdomainHit {
    pub host: String,
    pub sources: Vec<String>,
    pub ip: Option<IpAddr>,
}

#[derive(Debug, Default)]
pub struct EnumerationResult {
    pub subdomains: Vec<SubdomainHit>,
    pub stats: Stats,
}

pub struct Engine {
    cfg: Arc<RuntimeConfig>,
    registry: Arc<Registry>,
    session: Arc<Session>,
    resolver: Option<Arc<ActiveResolver>>,
    match_re: Vec<Regex>,
    filter_re: Vec<Regex>,
    ip_re: Regex,
}

impl Engine {
    pub async fn new(cfg: RuntimeConfig, registry: Registry) -> anyhow::Result<Self> {
        let session = Session::new(&cfg)?;
        let resolver = if cfg.active {
            Some(Arc::new(ActiveResolver::new(&cfg)?))
        } else {
            None
        };
        let match_re = compile(&cfg.match_regex, "match")?;
        let filter_re = compile(&cfg.filter_regex, "filter")?;
        let ip_re = Regex::new(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?$")?;
        Ok(Self {
            cfg: Arc::new(cfg),
            registry: Arc::new(registry),
            session,
            resolver,
            match_re,
            filter_re,
            ip_re,
        })
    }

    pub async fn enumerate(&self, domain: &str) -> anyhow::Result<EnumerationResult> {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            anyhow::bail!("empty domain");
        }
        let sources = self.registry.select(&self.cfg);
        if sources.is_empty() {
            anyhow::bail!("no sources selected");
        }
        if !std::env::var("LANCERSUB_QUIET").map(|v| v == "1").unwrap_or(false) {
            tracing::info!(
                "enumerating {} with {} sources: {}",
                domain,
                sources.len(),
                sources
                    .iter()
                    .map(|s| s.name())
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }

        let (tx, mut rx) = mpsc::channel::<Discovery>(2048);
        let started = Instant::now();
        let max_time = self.cfg.max_time;
        let session = self.session.clone();
        let domain_owned = domain.clone();

        // Spawn one task per source
        let mut handles = Vec::with_capacity(sources.len());
        for src in sources {
            let tx = tx.clone();
            let sess = session.clone();
            let dom = domain_owned.clone();
            let name = src.name().to_string();
            let h = tokio::spawn(async move {
                let mut stream = src.enumerate(&dom, sess.clone()).await;
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(host) => {
                            let _ = tx
                                .send(Discovery {
                                    host,
                                    source: name.clone(),
                                })
                                .await;
                        }
                        Err(e) => {
                            tracing::debug!("[{name}] error: {e:#}");
                        }
                    }
                }
            });
            handles.push(h);
        }
        drop(tx); // close once all producers go away

        let mut seen: IndexSet<String> = IndexSet::new();
        let mut source_map: HashMap<String, Vec<String>> = HashMap::new();

        let deadline = tokio::time::sleep(max_time);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(d) => self.accept(&domain, d, &mut seen, &mut source_map),
                        None => break,
                    }
                }
                _ = &mut deadline => {
                    tracing::warn!("max-time reached after {:?}, cancelling sources", started.elapsed());
                    for h in &handles { h.abort(); }
                    break;
                }
            }
        }
        // ensure producers complete
        for h in handles {
            let _ = h.await;
        }

        let mut hits: Vec<SubdomainHit> = seen
            .into_iter()
            .map(|host| SubdomainHit {
                sources: source_map.remove(&host).unwrap_or_default(),
                host,
                ip: None,
            })
            .collect();

        if let Some(res) = &self.resolver {
            hits = res.filter(&domain, hits, self.cfg.threads, self.cfg.no_wildcard).await?;
        }

        hits.sort_by(|a, b| a.host.cmp(&b.host));

        let stats = Stats::from_map(&self.session.stats);
        // Record results count per source
        let mut by_source: HashMap<String, usize> = HashMap::new();
        for h in &hits {
            for s in &h.sources {
                *by_source.entry(s.clone()).or_default() += 1;
            }
        }
        let mut final_stats = stats;
        for (k, v) in by_source {
            let entry = final_stats
                .per_source
                .entry(k)
                .or_insert_with(SourceStat::default);
            entry.results = v;
        }

        Ok(EnumerationResult {
            subdomains: hits,
            stats: final_stats,
        })
    }

    fn accept(
        &self,
        apex: &str,
        d: Discovery,
        seen: &mut IndexSet<String>,
        source_map: &mut HashMap<String, Vec<String>>,
    ) {
        let host = sanitize(&d.host);
        if host.is_empty() {
            return;
        }
        if !crate::extractor::is_subdomain(&host, apex) {
            return;
        }
        if self.cfg.exclude_ips && self.ip_re.is_match(&host) {
            return;
        }
        if !self.match_re.is_empty() && !self.match_re.iter().any(|r| r.is_match(&host)) {
            return;
        }
        if self.filter_re.iter().any(|r| r.is_match(&host)) {
            return;
        }
        let entry = source_map.entry(host.clone()).or_default();
        if !entry.contains(&d.source) {
            entry.push(d.source);
        }
        seen.insert(host);
    }
}

fn compile(patterns: &[String], kind: &str) -> anyhow::Result<Vec<Regex>> {
    patterns
        .iter()
        .map(|p| Regex::new(p).with_context(|| format!("invalid {kind} regex `{p}`")))
        .collect()
}

fn sanitize(host: &str) -> String {
    host.trim()
        .trim_end_matches('.')
        .trim_start_matches("*.")
        .to_ascii_lowercase()
}
