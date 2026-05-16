//! Shared HTTP `Session` — a `reqwest::Client` wrapped with random
//! user-agent, optional proxy, per-source rate limiting, and stats.

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;
use governor::{Quota, RateLimiter};
use rand::seq::SliceRandom;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::{Method, Response};

use crate::config::{RateLimitSpec, RuntimeConfig};
use crate::stats::SourceStat;

type KeyedLimiter = RateLimiter<String, DashMapStateStore<String>, DefaultClock>;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "lancer-subfinder/0.1 (+https://github.com/NHTanvir/lancer-subfinder)",
];

pub fn random_ua() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS.choose(&mut rng).copied().unwrap_or(USER_AGENTS[0])
}

#[derive(Debug, Clone, Default)]
pub struct RateMap(HashMap<String, RateLimitSpec>);

impl RateMap {
    pub fn defaults() -> Self {
        use Duration as D;
        let mut m = HashMap::new();
        let mut add = |k: &str, n: u32, per: D| {
            m.insert(
                k.to_string(),
                RateLimitSpec {
                    events: n,
                    per,
                },
            );
        };
        add("github", 83, D::from_secs(60));
        add("hackertarget", 2, D::from_secs(1));
        add("securitytrails", 2, D::from_secs(1));
        add("virustotal", 4, D::from_secs(60));
        add("whoisxmlapi", 50, D::from_secs(1));
        add("urlscan", 1, D::from_secs(1));
        add("shodan", 1, D::from_secs(1));
        add("sitedossier", 8, D::from_secs(60));
        add("waybackarchive", 15, D::from_secs(60));
        add("certspotter", 100, D::from_secs(3600));
        add("censys", 1, D::from_secs(1));
        add("commoncrawl", 1, D::from_secs(2));
        add("hudsonrock", 5, D::from_secs(1));
        add("pugrecon", 10, D::from_secs(1));
        add("c99", 1, D::from_secs(2));
        Self(m)
    }

    pub fn overlay(&mut self, other: &HashMap<String, RateLimitSpec>) {
        for (k, v) in other {
            self.0.insert(k.to_ascii_lowercase(), v.clone());
        }
    }

    pub fn get(&self, source: &str) -> Option<&RateLimitSpec> {
        self.0.get(&source.to_ascii_lowercase())
    }
}

pub struct Session {
    client: reqwest::Client,
    limiters: Arc<DashMap<String, Arc<KeyedLimiter>>>,
    rate_map: RateMap,
    global: Option<Arc<KeyedLimiter>>, // single "_global" bucket
    pub stats: Arc<DashMap<String, SourceStat>>,
}

impl Session {
    pub fn new(cfg: &RuntimeConfig) -> anyhow::Result<Arc<Self>> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(random_ua()));

        let mut builder = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .pool_max_idle_per_host(100)
            .danger_accept_invalid_certs(false)
            .default_headers(headers)
            .gzip(true);

        if let Some(p) = &cfg.proxy {
            builder = builder.proxy(reqwest::Proxy::all(p)?);
        }
        let client = builder.build()?;

        let mut rate_map = RateMap::defaults();
        rate_map.overlay(&cfg.rate_limits);

        let global = cfg.global_rate_limit.and_then(|n| {
            NonZeroU32::new(n).map(|n| {
                let q = Quota::per_second(n);
                Arc::new(RateLimiter::dashmap_with_clock(q, &DefaultClock::default()))
            })
        });

        Ok(Arc::new(Self {
            client,
            limiters: Arc::new(DashMap::new()),
            rate_map,
            global,
            stats: Arc::new(DashMap::new()),
        }))
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn limiter_for(&self, source: &str) -> Option<Arc<KeyedLimiter>> {
        let spec = self.rate_map.get(source)?;
        let key = source.to_ascii_lowercase();
        if let Some(l) = self.limiters.get(&key) {
            return Some(l.clone());
        }
        let events = NonZeroU32::new(spec.events).unwrap_or(NonZeroU32::new(1).unwrap());
        // governor Quota: per `per` duration with `events` burst.
        let q = Quota::with_period(spec.per / spec.events.max(1))
            .unwrap_or_else(|| Quota::per_second(events))
            .allow_burst(events);
        let lim = Arc::new(RateLimiter::dashmap_with_clock(q, &DefaultClock::default()));
        self.limiters.insert(key, lim.clone());
        Some(lim)
    }

    /// Wait for rate-limit quota for this source (+ global), then return.
    pub async fn throttle(&self, source: &str) {
        if let Some(l) = self.limiter_for(source) {
            l.until_key_ready(&source.to_ascii_lowercase()).await;
        }
        if let Some(g) = &self.global {
            g.until_key_ready(&"_global".to_string()).await;
        }
    }

    /// GET helper — throttle, send, return Response (status + body).
    pub async fn get(&self, source: &str, url: &str) -> anyhow::Result<Response> {
        self.req(source, Method::GET, url, None, &[]).await
    }

    /// POST helper.
    pub async fn post_json(
        &self,
        source: &str,
        url: &str,
        body: serde_json::Value,
        headers: &[(&str, String)],
    ) -> anyhow::Result<Response> {
        self.req(source, Method::POST, url, Some(body), headers).await
    }

    pub async fn req(
        &self,
        source: &str,
        method: Method,
        url: &str,
        body: Option<serde_json::Value>,
        headers: &[(&str, String)],
    ) -> anyhow::Result<Response> {
        self.throttle(source).await;
        let t0 = Instant::now();

        let build_req = |m: Method| {
            let mut r = self.client.request(m, url);
            for (k, v) in headers {
                r = r.header(*k, v);
            }
            if let Some(ref b) = body {
                r = r.json(b);
            }
            r
        };

        let resp = build_req(method.clone()).send().await;
        let elapsed = t0.elapsed();

        // Accumulate stats; drop the lock before the async retry path.
        {
            let mut entry = self.stats.entry(source.to_string()).or_default();
            entry.requests += 1;
            entry.elapsed += elapsed;
            match &resp {
                Err(_) => entry.errors += 1,
                Ok(r) if !r.status().is_success() && r.status() != reqwest::StatusCode::NOT_FOUND => {
                    entry.errors += 1;
                }
                _ => {}
            }
        } // lock released here

        match resp {
            Ok(r) if r.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                // Phase 3: honor Retry-After and do one retry
                let wait_secs = r
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(60)
                    .min(300);
                tracing::debug!("[{source}] 429 — waiting {wait_secs}s before retry");
                tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                self.throttle(source).await;
                let t1 = Instant::now();
                let resp2 = build_req(method).send().await;
                let elapsed2 = t1.elapsed();
                let result = match resp2 {
                    Ok(r2) => Ok(r2),
                    Err(e) => Err(anyhow::Error::from(e)),
                };
                {
                    let mut e2 = self.stats.entry(source.to_string()).or_default();
                    e2.requests += 1;
                    e2.elapsed += elapsed2;
                    match &result {
                        Err(_) => e2.errors += 1,
                        Ok(r2) if !r2.status().is_success() && r2.status() != reqwest::StatusCode::NOT_FOUND => {
                            e2.errors += 1;
                        }
                        _ => {}
                    }
                }
                result
            }
            Ok(r) => Ok(r),
            Err(e) => Err(e.into()),
        }
    }

    pub fn record_results(&self, source: &str, n: usize) {
        let mut entry = self.stats.entry(source.to_string()).or_default();
        entry.results += n;
    }
}
