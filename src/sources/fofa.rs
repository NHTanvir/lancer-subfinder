use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Fofa {
    keys: Vec<String>,
    rr: AtomicUsize,
}

fn b64_encode(s: &str) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b = match chunk.len() {
            3 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32),
            2 => ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8),
            1 => (chunk[0] as u32) << 16,
            _ => unreachable!(),
        };
        out.push(CHARS[((b >> 18) & 63) as usize] as char);
        out.push(CHARS[((b >> 12) & 63) as usize] as char);
        out.push(if chunk.len() >= 2 { CHARS[((b >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() >= 3 { CHARS[(b & 63) as usize] as char } else { '=' });
    }
    out
}

#[async_trait::async_trait]
impl Source for Fofa {
    fn name(&self) -> &'static str {
        "fofa"
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
        let raw_key = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return empty_stream(),
        };

        // Keys stored as "email:api_key"
        let (email, api_key) = match raw_key.splitn(2, ':').collect::<Vec<_>>().as_slice() {
            [e, k] => (e.to_string(), k.to_string()),
            _ => return empty_stream(),
        };

        let query = format!("domain=\"{domain}\"");
        let qbase64 = b64_encode(&query);

        let url = format!(
            "https://fofa.info/api/v1/search/all?email={email}&key={api_key}&qbase64={qbase64}&size=10000&fields=host"
        );

        let resp = match session
            .req(self.name(), reqwest::Method::GET, &url, None, &[])
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
            if let Some(results) = val.get("results").and_then(|r| r.as_array()) {
                for item in results {
                    // Each item may be ["host"] (array) or "host" (string)
                    let host = if let Some(arr) = item.as_array() {
                        arr.first().and_then(|v| v.as_str()).map(|s| s.to_string())
                    } else {
                        item.as_str().map(|s| s.to_string())
                    };
                    if let Some(h) = host {
                        let h = h.trim().to_ascii_lowercase();
                        // Strip port if present (e.g. "sub.example.com:8080" → "sub.example.com")
                        let h = h.split(':').next().unwrap_or("").to_string();
                        if !h.is_empty() && extractor::is_subdomain(&h, domain) {
                            all.push(h);
                        }
                    }
                }
            }
        }

        // Fallback: extract from raw text
        if all.is_empty() {
            all.extend(extractor::extract(&text, domain));
        }

        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
