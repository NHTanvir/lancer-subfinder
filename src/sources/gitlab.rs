use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct GitLab {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[async_trait::async_trait]
impl Source for GitLab {
    fn name(&self) -> &'static str {
        "gitlab"
    }
    fn is_default(&self) -> bool {
        false
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Optional
    }
    fn has_keys(&self) -> bool {
        true // Works without key (limited)
    }
    fn set_keys(&mut self, keys: Vec<String>) {
        self.keys = keys;
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let mut out = Vec::new();

        // Build auth header string once (same key used across pages)
        let auth_value: Option<String> = super::next_key(&self.keys, &self.rr)
            .map(|key| format!("Bearer {key}"));

        for page in 1u32..=5 {
            let url = format!(
                "https://gitlab.com/api/v4/search?scope=blobs&search={domain}&per_page=100&page={page}"
            );

            let headers: Vec<(&str, String)> = match &auth_value {
                Some(v) => vec![("Authorization", v.clone())],
                None => vec![],
            };

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

            let items: Vec<serde_json::Value> = match resp.json().await {
                Ok(v) => v,
                Err(_) => break,
            };

            if items.is_empty() {
                break;
            }

            for item in &items {
                if let Some(data) = item.get("data").and_then(|v| v.as_str()) {
                    out.extend(extractor::extract(data, domain));
                }
                if let Some(path) = item.get("path").and_then(|v| v.as_str()) {
                    out.extend(extractor::extract(path, domain));
                }
            }
        }

        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
