use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Profundis {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[async_trait::async_trait]
impl Source for Profundis {
    fn name(&self) -> &'static str {
        "profundis"
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
        let key = match super::next_key(&self.keys, &self.rr) {
            Some(k) => k,
            None => return super::empty_stream(),
        };

        let url = format!("https://api.profundis.dev/api/v1/subdomains?domain={domain}");
        let resp = match session
            .req(
                self.name(),
                reqwest::Method::GET,
                &url,
                None,
                &[("Authorization", format!("Bearer {key}"))],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        if !resp.status().is_success() {
            return super::empty_stream();
        }
        let text = resp.text().await.unwrap_or_default();
        let out = crate::extractor::extract(&text, domain);
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
