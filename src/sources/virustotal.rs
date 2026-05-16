use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct VirusTotal {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    data: Option<Vec<Datum>>,
    meta: Option<Meta>,
}
#[derive(Deserialize)]
struct Datum {
    id: Option<String>,
}
#[derive(Deserialize)]
struct Meta {
    cursor: Option<String>,
}

#[async_trait::async_trait]
impl Source for VirusTotal {
    fn name(&self) -> &'static str {
        "virustotal"
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

        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..25 {
            let url = match &cursor {
                Some(c) => format!(
                    "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40&cursor={c}"
                ),
                None => format!(
                    "https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
                ),
            };
            let resp = match session
                .req(
                    self.name(),
                    reqwest::Method::GET,
                    &url,
                    None,
                    &[("x-apikey", key.clone())],
                )
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
            let data = parsed.data.unwrap_or_default();
            if data.is_empty() {
                break;
            }
            for d in data {
                if let Some(id) = d.id {
                    let h = id.trim().to_ascii_lowercase();
                    if crate::extractor::is_subdomain(&h, domain) {
                        all.push(h);
                    }
                }
            }
            cursor = parsed.meta.and_then(|m| m.cursor);
            if cursor.is_none() {
                break;
            }
        }
        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
