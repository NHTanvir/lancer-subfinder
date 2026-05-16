use std::sync::Arc;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Anubis;

#[async_trait::async_trait]
impl Source for Anubis {
    fn name(&self) -> &'static str {
        "anubis"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://jonlu.ca/anubis/subdomains/{domain}");
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(_) => return super::empty_stream(),
        };
        let hosts: Vec<String> = resp.json().await.unwrap_or_default();
        let out: Vec<String> = hosts
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| crate::extractor::is_subdomain(h, domain))
            .collect();
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
