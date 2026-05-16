use std::sync::Arc;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct RapidDns;

#[async_trait::async_trait]
impl Source for RapidDns {
    fn name(&self) -> &'static str {
        "rapiddns"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false // Cloudflare-gated; only with -all
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://rapiddns.io/subdomain/{domain}?full=1");
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(_) => return super::empty_stream(),
        };
        let body = resp.text().await.unwrap_or_default();
        let hosts = extractor::extract(&body, domain);
        session.record_results(self.name(), hosts.len());
        ok_stream(hosts)
    }
}
