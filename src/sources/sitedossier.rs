use std::sync::Arc;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct SiteDossier;

#[async_trait::async_trait]
impl Source for SiteDossier {
    fn name(&self) -> &'static str {
        "sitedossier"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let mut all = Vec::new();
        // pages of 100; cap at 5 pages.
        for page in (1..=500).step_by(100) {
            let url = format!("http://www.sitedossier.com/parentdomain/{domain}/{page}");
            let resp = match session.get(self.name(), &url).await {
                Ok(r) => r,
                Err(_) => break,
            };
            let body = resp.text().await.unwrap_or_default();
            let hosts = extractor::extract(&body, domain);
            if hosts.is_empty() {
                break;
            }
            all.extend(hosts);
        }
        all.sort();
        all.dedup();
        session.record_results(self.name(), all.len());
        ok_stream(all)
    }
}
