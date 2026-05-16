//! Censys Platform API v3. Key form: "PAT:OrgID".

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;
use serde_json::json;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Censys {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    result: Option<ResultBody>,
}
#[derive(Deserialize)]
struct ResultBody {
    hits: Option<Vec<Hit>>,
    next_cursor: Option<String>,
}
#[derive(Deserialize)]
struct Hit {
    #[serde(default)]
    parsed_names: Vec<String>,
    #[serde(default)]
    names: Vec<String>,
}

#[async_trait::async_trait]
impl Source for Censys {
    fn name(&self) -> &'static str {
        "censys"
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
    fn has_recursive_support(&self) -> bool {
        true
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let raw = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return super::empty_stream(),
        };
        let (pat, org) = match raw.split_once(':') {
            Some((p, o)) => (p.to_string(), o.to_string()),
            None => (raw.clone(), String::new()),
        };

        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let body = json!({
                "query": format!("cert.names: {domain}"),
                "page_size": 100,
                "cursor": cursor,
            });
            let headers = vec![
                ("Authorization", format!("Bearer {pat}")),
                ("X-Organization-ID", org.clone()),
                ("Content-Type", "application/json".into()),
            ];
            let url = "https://api.platform.censys.io/v3/global/search/query";
            let resp = match session
                .post_json(self.name(), url, body, &headers)
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
            let result = match parsed.result {
                Some(r) => r,
                None => break,
            };
            for h in result.hits.unwrap_or_default() {
                for n in h.parsed_names.into_iter().chain(h.names.into_iter()) {
                    let n = n.trim_start_matches("*.").to_ascii_lowercase();
                    if crate::extractor::is_subdomain(&n, domain) {
                        all.push(n);
                    }
                }
            }
            cursor = result.next_cursor;
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
