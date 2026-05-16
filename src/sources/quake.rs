use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Quake {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[async_trait::async_trait]
impl Source for Quake {
    fn name(&self) -> &'static str {
        "quake"
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

        let url = "https://quake.360.cn/api/v3/search/quake_service";
        let body = serde_json::json!({
            "query": format!("domain:\"{domain}\""),
            "size": 500
        });
        let headers = vec![("X-QuakeToken", key)];

        let resp = match session
            .req(self.name(), reqwest::Method::POST, url, Some(body), &headers)
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

        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
            if let Some(data) = val.get("data").and_then(|d| d.as_array()) {
                for item in data {
                    if let Some(host) = item
                        .get("service")
                        .and_then(|s| s.get("http"))
                        .and_then(|h| h.get("host"))
                        .and_then(|v| v.as_str())
                    {
                        let h = host.trim().to_ascii_lowercase();
                        if extractor::is_subdomain(&h, domain) {
                            all.push(h);
                        }
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
