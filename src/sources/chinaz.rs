use std::sync::Arc;
use std::sync::atomic::AtomicUsize;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, empty_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct ChinaZ {
    keys: Vec<String>,
    rr: AtomicUsize,
}

#[async_trait::async_trait]
impl Source for ChinaZ {
    fn name(&self) -> &'static str {
        "chinaz"
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
            None => return empty_stream(),
        };

        let url = format!(
            "https://apidata.chinaz.com/CallAPI/Alexa?key={key}&domain={domain}"
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

        let mut all = extractor::extract(&text, domain);
        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
