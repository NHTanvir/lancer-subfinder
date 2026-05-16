use std::sync::Arc;

use crate::extractor;
use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct WaybackArchive;

#[async_trait::async_trait]
impl Source for WaybackArchive {
    fn name(&self) -> &'static str {
        "waybackarchive"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::None
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!(
            "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=txt&fl=original&collapse=urlkey&limit=20000"
        );
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
