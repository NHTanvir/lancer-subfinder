use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct LeakIX {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Entry {
    subdomain: Option<String>,
}

#[async_trait::async_trait]
impl Source for LeakIX {
    fn name(&self) -> &'static str {
        "leakix"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Optional
    }
    fn set_keys(&mut self, keys: Vec<String>) {
        self.keys = keys;
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://leakix.net/api/subdomains/{domain}");
        let mut headers = vec![("Accept", "application/json".to_string())];
        if let Some(k) = super::next_key(&self.keys, &self.rr) {
            headers.push(("api-key", k));
        }
        let resp = match session
            .req(self.name(), reqwest::Method::GET, &url, None, &headers)
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let entries: Vec<Entry> = resp.json().await.unwrap_or_default();
        let out: Vec<String> = entries
            .into_iter()
            .filter_map(|e| e.subdomain)
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
