use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct DnsDb {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[async_trait::async_trait]
impl Source for DnsDb {
    fn name(&self) -> &'static str {
        "dnsdb"
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

        let url = format!(
            "https://api.dnsdb.info/lookup/rrset/name/*.{domain}/ANY?limit=10000"
        );
        let headers = vec![
            ("X-API-Key", key),
            ("Accept", "application/x-ndjson".to_string()),
        ];

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

        // Parse JSON-lines (ndjson)
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(rrname) = val.get("rrname").and_then(|v| v.as_str()) {
                    // Strip trailing dot
                    let h = rrname.trim_end_matches('.').to_ascii_lowercase();
                    if extractor::is_subdomain(&h, domain) {
                        all.push(h);
                    }
                }
            }
        }

        // Fallback: extract from whole text
        if all.is_empty() {
            all.extend(extractor::extract(&text, domain));
        }

        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
