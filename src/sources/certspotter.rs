use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct CertSpotter {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Entry {
    dns_names: Vec<String>,
}

#[async_trait::async_trait]
impl Source for CertSpotter {
    fn name(&self) -> &'static str {
        "certspotter"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Optional
    }
    fn has_recursive_support(&self) -> bool {
        true
    }
    fn set_keys(&mut self, keys: Vec<String>) {
        self.keys = keys;
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let mut headers = Vec::new();
        if let Some(k) = super::next_key(&self.keys, &self.rr) {
            headers.push(("Authorization", format!("Bearer {k}")));
        }
        let url = format!(
            "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        );
        let resp = match session
            .req(self.name(), reqwest::Method::GET, &url, None, &headers)
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let entries: Vec<Entry> = match resp.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        let mut out = Vec::new();
        for e in entries {
            for h in e.dns_names {
                let h = h.trim_start_matches("*.").to_ascii_lowercase();
                if crate::extractor::is_subdomain(&h, domain) {
                    out.push(h);
                }
            }
        }
        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
