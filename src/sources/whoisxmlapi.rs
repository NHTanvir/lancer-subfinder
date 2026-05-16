use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct WhoisXmlApi {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    result: Option<Body>,
}
#[derive(Deserialize)]
struct Body {
    records: Option<Vec<Rec>>,
}
#[derive(Deserialize)]
struct Rec {
    domain: Option<String>,
}

#[async_trait::async_trait]
impl Source for WhoisXmlApi {
    fn name(&self) -> &'static str {
        "whoisxmlapi"
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
        let url = format!(
            "https://subdomains.whoisxmlapi.com/api/v1?apiKey={key}&domainName={domain}"
        );
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = resp.json().await.unwrap_or(Resp { result: None });
        let out: Vec<String> = parsed
            .result
            .and_then(|r| r.records)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| r.domain)
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
