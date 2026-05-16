//! Active mode: resolve candidates and filter wildcards.
//!
//! Wildcard detection mirrors subfinder/dnsx:
//!   - For each candidate's parent, probe three random `<sha1>.<parent>`
//!     hosts; the union of their A-records is the wildcard IP-set.
//!   - Drop final results whose resolved A-set is a subset of the
//!     wildcard set (and non-empty intersection).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::TokioAsyncResolver;
use rand::Rng;
use sha1::{Digest, Sha1};

use crate::config::RuntimeConfig;
use crate::engine::SubdomainHit;

pub struct ActiveResolver {
    resolver: TokioAsyncResolver,
}

impl ActiveResolver {
    pub fn new(cfg: &RuntimeConfig) -> anyhow::Result<Self> {
        let mut group = NameServerConfigGroup::new();
        for r in &cfg.resolvers {
            let addr = parse_resolver(r)?;
            group.push(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
            group.push(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
        }
        let resolver_cfg = ResolverConfig::from_parts(None, vec![], group);
        let mut opts = ResolverOpts::default();
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.use_hosts_file = false;
        let resolver = TokioAsyncResolver::tokio(resolver_cfg, opts);
        Ok(Self { resolver })
    }

    pub async fn filter(
        &self,
        apex: &str,
        hits: Vec<SubdomainHit>,
        concurrency: usize,
        no_wildcard: bool,
    ) -> anyhow::Result<Vec<SubdomainHit>> {
        if hits.is_empty() {
            return Ok(hits);
        }
        let concurrency = concurrency.max(1);
        // Resolve everything in parallel batches.
        let mut resolved: Vec<(SubdomainHit, Vec<IpAddr>)> = Vec::with_capacity(hits.len());
        let resolver = self.resolver.clone();
        let mut futures = futures::stream::FuturesUnordered::new();
        let mut iter = hits.into_iter();

        // Prime
        for _ in 0..concurrency {
            if let Some(h) = iter.next() {
                let r = resolver.clone();
                futures.push(tokio::spawn(async move {
                    let ips = resolve_ips(&r, &h.host).await;
                    (h, ips)
                }));
            }
        }
        use futures::StreamExt;
        while let Some(joined) = futures.next().await {
            if let Ok((mut h, ips)) = joined {
                if !ips.is_empty() {
                    h.ip = Some(ips[0]);
                    resolved.push((h, ips));
                }
                if let Some(n) = iter.next() {
                    let r = resolver.clone();
                    futures.push(tokio::spawn(async move {
                        let ips = resolve_ips(&r, &n.host).await;
                        (n, ips)
                    }));
                }
            }
        }

        if !no_wildcard {
            return Ok(resolved.into_iter().map(|(h, _)| h).collect());
        }

        // Build wildcard sets per parent zone.
        let mut wildcard_cache: HashMap<String, HashSet<IpAddr>> = HashMap::new();
        let mut kept = Vec::with_capacity(resolved.len());
        for (hit, ips) in resolved {
            let parent = parent_of(&hit.host, apex);
            let wc_set = match wildcard_cache.get(&parent) {
                Some(s) => s.clone(),
                None => {
                    let s = self.probe_wildcard(&parent).await;
                    wildcard_cache.insert(parent.clone(), s.clone());
                    s
                }
            };
            if !wc_set.is_empty() {
                let cand: HashSet<IpAddr> = ips.iter().copied().collect();
                if !cand.is_empty() && cand.is_subset(&wc_set) {
                    continue;
                }
            }
            kept.push(hit);
        }
        Ok(kept)
    }

    async fn probe_wildcard(&self, parent: &str) -> HashSet<IpAddr> {
        let mut set = HashSet::new();
        for _ in 0..3 {
            let mut rng = rand::thread_rng();
            let mut h = Sha1::new();
            let n: u64 = rng.gen();
            h.update(n.to_le_bytes());
            let probe = format!("{}.{}", hex::encode(&h.finalize()[..8]), parent);
            let ips = resolve_ips(&self.resolver, &probe).await;
            for ip in ips {
                set.insert(ip);
            }
        }
        set
    }
}

async fn resolve_ips(resolver: &TokioAsyncResolver, host: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    if let Ok(lookup) = resolver.lookup_ip(host).await {
        for ip in lookup.iter() {
            out.push(ip);
        }
    }
    out
}

fn parent_of(host: &str, apex: &str) -> String {
    // Wildcards are typically applied at a level, e.g. `*.us-east.acme.com`.
    // We probe the immediate parent of `host`; if that == apex, that's fine.
    match host.split_once('.') {
        Some((_, rest)) if rest.len() >= apex.len() => rest.to_string(),
        _ => apex.to_string(),
    }
}

fn parse_resolver(s: &str) -> anyhow::Result<std::net::SocketAddr> {
    let s = s.trim();
    if let Ok(sa) = s.parse::<std::net::SocketAddr>() {
        return Ok(sa);
    }
    let ip: IpAddr = s.parse()?;
    Ok(std::net::SocketAddr::new(ip, 53))
}
