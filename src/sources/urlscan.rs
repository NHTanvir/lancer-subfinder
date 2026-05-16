use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct UrlScan {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    results: Option<Vec<Hit>>,
}
#[derive(Deserialize)]
struct Hit {
    page: Option<Page>,
}
#[derive(Deserialize)]
struct Page {
    domain: Option<String>,
    url: Option<String>,
}

#[async_trait::async_trait]
impl Source for UrlScan {
    fn name(&self) -> &'static str {
        "urlscan"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Optional
    }
    fn set_keys(&mut self, keys: Vec<String>) {
        self.keys = keys;
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100");
        let mut headers = Vec::new();
        if let Some(k) = super::next_key(&self.keys, &self.rr) {
            headers.push(("API-Key", k));
        }
        let resp = match session
            .req(self.name(), reqwest::Method::GET, &url, None, &headers)
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = match resp.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        let mut out = Vec::new();
        for h in parsed.results.unwrap_or_default() {
            if let Some(p) = h.page {
                if let Some(d) = p.domain {
                    let d = d.to_ascii_lowercase();
                    if crate::extractor::is_subdomain(&d, domain) {
                        out.push(d);
                    }
                }
                if let Some(u) = p.url {
                    out.extend(crate::extractor::extract(&u, domain));
                }
            }
        }
        out.sort();
        out.dedup();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
