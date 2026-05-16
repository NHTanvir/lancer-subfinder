use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use serde::Deserialize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Netlas {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[derive(Deserialize)]
struct Resp {
    items: Option<Vec<Item>>,
}
#[derive(Deserialize)]
struct Item {
    data: Option<Data>,
}
#[derive(Deserialize)]
struct Data {
    domain: Option<String>,
}

#[async_trait::async_trait]
impl Source for Netlas {
    fn name(&self) -> &'static str {
        "netlas"
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
        // Community-plan cap: keep responses small (size=100, 1 page).
        let url = format!(
            "https://app.netlas.io/api/domains/?q=domain:*.{domain}&size=100&source_type=include&fields=*"
        );
        let resp = match session
            .req(
                self.name(),
                reqwest::Method::GET,
                &url,
                None,
                &[("X-API-Key", key)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let parsed: Resp = resp.json().await.unwrap_or(Resp { items: None });
        let out: Vec<String> = parsed
            .items
            .unwrap_or_default()
            .into_iter()
            .filter_map(|i| i.data.and_then(|d| d.domain))
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
