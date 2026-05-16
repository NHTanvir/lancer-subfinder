use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct C99 {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    subdomains: Option<Vec<Entry>>,
}
#[derive(Deserialize)]
struct Entry {
    subdomain: Option<String>,
}

#[async_trait::async_trait]
impl Source for C99 {
    fn name(&self) -> &'static str {
        "c99"
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
        let url = format!("https://api.c99.nl/subdomainfinder?key={key}&domain={domain}&json");
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = resp.json().await.unwrap_or(Resp { subdomains: None });
        let out: Vec<String> = parsed
            .subdomains
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| e.subdomain)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|h| crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
