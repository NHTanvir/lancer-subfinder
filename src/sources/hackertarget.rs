use std::sync::Arc;

use crate::session::Session;

use super::{ok_stream, KeyRequirement, Source, SubStream};

#[derive(Default)]
pub struct HackerTarget;

#[async_trait::async_trait]
impl Source for HackerTarget {
    fn name(&self) -> &'static str {
        "hackertarget"
    }
    fn key_requirement(&self) -> KeyRequirement {
        KeyRequirement::Optional
    }

    async fn enumerate(&self, domain: &str, session: Arc<Session>) -> SubStream {
        let url = format!("https://api.hackertarget.com/hostsearch/?q={domain}");
        let resp = match session.get(self.name(), &url).await {
            Ok(r) => r,
            Err(e) => return super::err_stream(e),
        };
        let body = resp.text().await.unwrap_or_default();
        let mut out = Vec::new();
        for line in body.lines() {
            if let Some((host, _ip)) = line.split_once(',') {
                let h = host.trim().to_ascii_lowercase();
                if !h.is_empty() && crate::extractor::is_subdomain(&h, domain) {
                    out.push(h);
                }
            }
        }
        session.record_results(self.name(), out.len());
        ok_stream(out)
    }
}
