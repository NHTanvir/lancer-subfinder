//! IntelX phonebook search (two-step: start search, fetch results).

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct IntelX {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Start {
    id: Option<String>,
}
#[derive(Deserialize)]
struct Results {
    selectors: Option<Vec<Selector>>,
    status: Option<i32>,
}
#[derive(Deserialize)]
struct Selector {
    selectorvalue: String,
}

#[async_trait::async_trait]
impl Source for IntelX {
    fn name(&self) -> &'static str {
        "intelx"
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
        let start_url = "https://2.intelx.io/phonebook/search";
        let start_body = json!({
            "term": domain,
            "maxresults": 10000,
            "media": 0,
            "target": 1,
            "timeout": 20,
        });
        let resp = match session
            .post_json(self.name(), start_url, start_body, &[("x-key", key.clone())])
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let start: Start = match resp.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        let id = match start.id {
            Some(i) => i,
            None => return super::empty_stream(),
        };
        let mut out = Vec::new();
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let url = format!(
                "https://2.intelx.io/phonebook/search/result?id={id}&limit=10000"
            );
            let resp = match session
                .req(
                    self.name(),
                    reqwest::Method::GET,
                    &url,
                    None,
                    &[("x-key", key.clone())],
                )
                .await
            {
                Ok(r) => r,
                Err(_) => break,
            };
            let parsed: Results = match resp.json().await {
                Ok(v) => v,
                Err(_) => break,
            };
            for s in parsed.selectors.unwrap_or_default() {
                let h = s.selectorvalue.trim().to_ascii_lowercase();
                if crate::extractor::is_subdomain(&h, domain) {
                    out.push(h);
                }
            }
            if matches!(parsed.status, Some(0) | Some(1)) {
                break;
            }
        }
        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
