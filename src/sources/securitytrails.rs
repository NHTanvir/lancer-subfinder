use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct SecurityTrails {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    subdomains: Option<Vec<String>>,
}

#[async_trait::async_trait]
impl Source for SecurityTrails {
    fn name(&self) -> &'static str {
        "securitytrails"
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
        let key = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return super::empty_stream(),
        };
        // /v1/domain/{d}/subdomains is the simple endpoint; the scroll API is paid.
        let url = format!(
            "https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
        );
        let resp = match session
            .req(
                self.name(),
                reqwest::Method::GET,
                &url,
                None,
                &[("APIKEY", key)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = match resp.json().await {
            Ok(v) => v,
            Err(_) => return super::empty_stream(),
        };
        let out: Vec<String> = parsed
            .subdomains
            .unwrap_or_default()
            .into_iter()
            .map(|s| format!("{}.{domain}", s.trim()))
            .filter(|h| crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
