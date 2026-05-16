use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Chaos {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    domain: Option<String>,
    subdomains: Option<Vec<String>>,
}

#[async_trait::async_trait]
impl Source for Chaos {
    fn name(&self) -> &'static str {
        "chaos"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Required
    }
    fn has_keys(&self) -> bool {
        !self.keys.is_empty()
    }
    fn set_keys(&mut self, keys: Vec<String>) {
        self.keys = keys;
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let key = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return super::empty_stream(),
        };
        let url = format!("https://dns.projectdiscovery.io/dns/{domain}/subdomains");
        let resp = match session
            .req(
                self.name(),
                reqwest::Method::GET,
                &url,
                None,
                &[("Authorization", key)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = match resp.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        let apex = parsed.domain.unwrap_or_else(|| domain.to_string());
        let out: Vec<String> = parsed
            .subdomains
            .unwrap_or_default()
            .into_iter()
            .map(|s| format!("{}.{apex}", s.trim()))
            .filter(|h| crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
