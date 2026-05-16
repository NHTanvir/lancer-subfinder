use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Onyphe {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    results: Option<Vec<Entry>>,
}

#[derive(Deserialize)]
struct Entry {
    domain: Option<String>,
}

#[async_trait::async_trait]
impl Source for Onyphe {
    fn name(&self) -> &'static str {
        "onyphe"
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

        let url = format!("https://www.onyphe.io/api/v2/summary/domain/{domain}");
        let headers = vec![("Authorization", format!("Bearer {key}"))];

        let resp = match session
            .req(self.name(), reqwest::Method::GET, &url, None, &headers)
            .await
        {
            Ok(r) => r,
            Err(_) => return empty_stream(),
        };
        if !resp.status().is_success() {
            return empty_stream();
        }

        let text = match resp.text().await {
            Ok(t) => t,
            Err(_) => return empty_stream(),
        };

        let mut all = Vec::new();

        if let Ok(parsed) = serde_json::from_str::<Resp>(&text) {
            for entry in parsed.results.unwrap_or_default() {
                if let Some(d) = entry.domain {
                    let d = d.trim().to_ascii_lowercase();
                    if extractor::is_subdomain(&d, domain) {
                        all.push(d);
                    }
                }
            }
        }

        // Fallback
        if all.is_empty() {
            all.extend(extractor::extract(&text, domain));
        }

        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
