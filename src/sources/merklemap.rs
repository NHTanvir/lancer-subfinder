use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct MerkleMap {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    results: Option<Vec<ResultEntry>>,
}

#[derive(Deserialize)]
struct ResultEntry {
    domain: Option<String>,
}

#[async_trait::async_trait]
impl Source for MerkleMap {
    fn name(&self) -> &'static str {
        "merklemap"
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
            None => return super::empty_stream(),
        };

        let url = format!("https://api.merklemap.com/v1/search?query=*.{domain}");
        let resp = match session
            .req(
                self.name(),
                reqwest::Method::GET,
                &url,
                None,
                &[("Authorization", format!("Bearer {key}"))],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        if !resp.status().is_success() {
            return super::empty_stream();
        }
        let text = resp.text().await.unwrap_or_default();

        // Try structured JSON parse first
        let mut out: Vec<String> = Vec::new();
        if let Ok(parsed) = serde_json::from_str::<Resp>(&text) {
            if let Some(results) = parsed.results {
                for entry in results {
                    if let Some(d) = entry.domain {
                        let d = d.trim().to_ascii_lowercase();
                        if !d.is_empty() && crate::extractor::is_subdomain(&d, domain) {
                            out.push(d);
                        }
                    }
                }
                out.sort();
                out.dedup();
            }
        }

        // Fall back to regex extractor if structured parse yielded nothing
        if out.is_empty() {
            out = crate::extractor::extract(&text, domain);
        }

        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
