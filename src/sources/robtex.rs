use std::sync::Arc;

use crate::extractor;
use crate::session::Session;

use super::{err_stream, ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Robtex;

#[async_trait::async_trait]
impl Source for Robtex {
    fn name(&self) -> &'static str {
        "robtex"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://www.robtex.com/dns-lookup/{domain}");
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return err_stream(anyhow::anyhow!("robtex GET failed: {e}")),
        };

        let text = resp.text().await.unwrap_or_default();
        let mut hosts = extractor::extract(&text, domain);
        hosts.sort();
        hosts.dedup();
        session.record_results(self.name(), hosts.len());
        ok_stream(hosts)
    }
}
