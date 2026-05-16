use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct RedHuntLabs {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    subdomains: Option<Vec<String>>,
    total: Option<usize>,
}

#[async_trait::async_trait]
impl Source for RedHuntLabs {
    fn name(&self) -> &'static str {
        "redhuntlabs"
    }
    fn is_default(&self) -> bool {
        false
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
            None => return empty_stream(),
        };

        let mut all = Vec::new();
        let page_size = 1000usize;
        let mut total: Option<usize> = None;

        for page in 1usize..=20 {
            let url = format!(
                "https://reconapi.redhuntlabs.com/community/v1/domains/subdomains?domain={domain}&page_size={page_size}&page={page}"
            );
            let headers = vec![("Authorization", format!("Bearer {key}"))];

            let resp = match session
                .req(self.name(), reqwest::Method::GET, &url, None, &headers)
                .await
            {
                Ok(r) => r,
                Err(_) => break,
            };
            if !resp.status().is_success() {
                break;
            }

            let parsed: Resp = match resp.json().await {
                Ok(v) => v,
                Err(_) => break,
            };

            if total.is_none() {
                total = parsed.total;
            }

            let subs = parsed.subdomains.unwrap_or_default();
            if subs.is_empty() {
                break;
            }

            for s in &subs {
                let h = s.trim().to_ascii_lowercase();
                if extractor::is_subdomain(&h, domain) {
                    all.push(h);
                }
            }

            // Stop if we've fetched all results
            if let Some(t) = total {
                if page * page_size >= t {
                    break;
                }
            }
        }

        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
