use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct BufferOver {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    #[serde(rename = "Results")]
    results: Option<Vec<String>>,
    #[serde(rename = "FDNS_A")]
    fdns_a: Option<Vec<String>>,
}

#[async_trait::async_trait]
impl Source for BufferOver {
    fn name(&self) -> &'static str {
        "bufferover"
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
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let key = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return super::empty_stream(),
        };
        let url = format!("https://tls.bufferover.run/dns?q=.{domain}");
        let resp = match session
            .req(
                self.name(),
                reqwest::Method::GET,
                &url,
                None,
                &[("x-api-key", key)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = resp.json().await.unwrap_or(Resp {
            results: None,
            fdns_a: None,
        });
        let mut out = Vec::new();
        for v in parsed
            .results
            .into_iter()
            .flatten()
            .chain(parsed.fdns_a.into_iter().flatten())
        {
            // entries look like "ip,host" or "ip,host,...".
            for part in v.split(',') {
                let h = part.trim().to_ascii_lowercase();
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
