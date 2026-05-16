use std::sync::Arc;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct Digitorus;

#[async_trait::async_trait]
impl Source for Digitorus {
    fn name(&self) -> &'static str {
        "digitorus"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn has_recursive_support(&self) -> bool {
        true
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://certificatedetails.com/{domain}");
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let body = resp.text().await.unwrap_or_default();
        let hosts = extractor::extract(&body, domain);
        session.record_results(self.name(), hosts.len());
        ok_stream(hosts)
    }
}
