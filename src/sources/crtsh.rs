//! crt.sh — Certificate Transparency. HTTP-only mode (Postgres dual-mode
//! is in the plan but kept HTTP-only here for portability / cross-compile).

use std::sync::Arc;

use serde::Deserialize;

use crate::extractor;
use crate::session::Session;

use super::{empty_stream, ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Crtsh;

#[derive(Deserialize)]
struct Entry {
    name_value: String,
}

#[async_trait::async_trait]
impl Source for Crtsh {
    fn name(&self) -> &'static str {
        "crtsh"
    }
    fn has_recursive_support(&self) -> bool {
        true
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!(
            "https://crt.sh/?q=%25.{}&output=json",
            urlencoding::encode_simple(domain)
        );
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        if !resp.status().is_success() {
            return empty_stream();
        }
        let text = match resp.text().await {
            Ok(t) => t,
            Err(e) => return super::err_stream(e.into()),
        };
        let entries: Vec<Entry> = serde_json::from_str(&text).unwrap_or_default();
        let mut out = Vec::with_capacity(entries.len() * 2);
        for e in entries {
            for line in e.name_value.split('\n') {
                let h = line.trim();
                if !h.is_empty() && extractor::is_subdomain(h, domain) {
                    out.push(h.trim_start_matches("*.").to_ascii_lowercase());
                }
            }
        }
        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}

/// Very small URL-encoder for paths (just enough for our use).
mod urlencoding {
    pub fn encode_simple(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | '~') {
                out.push(c);
            } else {
                for b in c.to_string().as_bytes() {
                    out.push_str(&format!("%{:02X}", b));
                }
            }
        }
        out
    }
}
