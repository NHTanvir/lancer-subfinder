use std::sync::Arc;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct DomainsProject;

#[async_trait::async_trait]
impl Source for DomainsProject {
    fn name(&self) -> &'static str {
        "domainsproject"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }
    fn is_default(&self) -> bool {
        false
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://www.domainsproject.org/lookup?d={domain}");
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
